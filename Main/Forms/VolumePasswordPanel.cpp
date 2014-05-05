/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "DaPlugDialog.h"
#include "KeyfilesDialog.h"
#include "VolumePasswordPanel.h"
#include "SecurityTokenKeyfilesDialog.h"

#include "Main/DaPlug/DaplugDongle.h"

namespace TrueCrypt
{
    VolumePasswordPanel::VolumePasswordPanel (wxWindow* parent, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles, bool enableCache, bool enablePassword, bool enableKeyfiles, bool enableConfirmation, bool enablePkcs5Prf, const wxString &passwordLabel, bool enableDaPlug)
        : VolumePasswordPanelBase (parent), Keyfiles (new KeyfileList), DaPlugFound (false), needConfirmation(enableConfirmation) /*[XaV]*/
	{
		if (keyfiles)
		{
			*Keyfiles = *keyfiles;
			UseKeyfilesCheckBox->SetValue (!Keyfiles->empty());
		}
		else
		{
			*Keyfiles = Gui->GetPreferences().DefaultKeyfiles;
			UseKeyfilesCheckBox->SetValue (Gui->GetPreferences().UseKeyfiles && !Keyfiles->empty());
		}

		PasswordTextCtrl->SetMaxLength (VolumePassword::MaxSize);
		ConfirmPasswordTextCtrl->SetMaxLength (VolumePassword::MaxSize);

		if (!passwordLabel.empty())
		{
			PasswordStaticText->SetLabel (passwordLabel);
			GridBagSizer->Detach (PasswordStaticText);
			GridBagSizer->Add (PasswordStaticText, wxGBPosition (0, 1), wxGBSpan (1, 1), wxALIGN_CENTER_VERTICAL | wxBOTTOM, Gui->GetDefaultBorderSize());
		}

		CacheCheckBox->Show (enableCache);
		
		if (!enablePassword && enableKeyfiles)
		{
			Layout();
			Fit();
			PasswordPlaceholderSizer->SetMinSize (wxSize (PasswordTextCtrl->GetSize().GetWidth(), -1));
		}
		else if (!enablePkcs5Prf)
		{
			GridBagSizer->Remove (PasswordPlaceholderSizer);
		}

		PasswordStaticText->Show (enablePassword);
		PasswordTextCtrl->Show (enablePassword);
		DisplayPasswordCheckBox->Show (enablePassword);

		ConfirmPasswordStaticText->Show (enableConfirmation);
		ConfirmPasswordTextCtrl->Show (enableConfirmation);
		
		UseKeyfilesCheckBox->Show (enableKeyfiles);
		KeyfilesButton->Show (enableKeyfiles);

        UseDaPlugCheckBox->Show (enableDaPlug); /*[XaV]*/
        DaPlugButton->Show (enableDaPlug);

		Pkcs5PrfStaticText->Show (enablePkcs5Prf);
		Pkcs5PrfChoice->Show (enablePkcs5Prf);

		if (enablePkcs5Prf)
		{	
			foreach_ref (const Pkcs5Kdf &kdf, Pkcs5Kdf::GetAvailableAlgorithms())
			{
				if (!kdf.IsDeprecated())
					Pkcs5PrfChoice->Append (kdf.GetName());
			}
			Pkcs5PrfChoice->Select (0);
		}

		if (!enablePkcs5Prf || (!enablePassword && !enableKeyfiles))
		{
			GridBagSizer->Remove (Pkcs5PrfSizer);
		}

		// Keyfiles drag & drop
		class FileDropTarget : public wxFileDropTarget
		{
		public:
			FileDropTarget (VolumePasswordPanel *panel) : Panel (panel) { }

			wxDragResult OnDragOver (wxCoord x, wxCoord y, wxDragResult def)
			{
				return wxDragLink;
			}

			bool OnDropFiles (wxCoord x, wxCoord y, const wxArrayString &filenames)
			{
				foreach (const wxString &f, filenames)
					Panel->AddKeyfile (make_shared <Keyfile> (wstring (f)));

				return true;
			}

		protected:
			VolumePasswordPanel *Panel;
		};

		if (enableKeyfiles)
		{
			SetDropTarget (new FileDropTarget (this));
#ifdef TC_MACOSX
			foreach (wxWindow *c, GetChildren())
				c->SetDropTarget (new FileDropTarget (this));
#endif
		}

		Layout();
		Fit();
	}

	VolumePasswordPanel::~VolumePasswordPanel ()
	{
		WipeTextCtrl (PasswordTextCtrl);
		WipeTextCtrl (ConfirmPasswordTextCtrl);
	}

	void VolumePasswordPanel::AddKeyfile (shared_ptr <Keyfile> keyfile)
	{
		if (!Keyfiles)
			Keyfiles.reset (new KeyfileList);

		Keyfiles->push_back (keyfile);
		UseKeyfilesCheckBox->SetValue (true);
	}

	void VolumePasswordPanel::DisplayPassword (bool display, wxTextCtrl **textCtrl, int row)
	{
		FreezeScope freeze (this);

		wxTextCtrl *newTextCtrl = new wxTextCtrl (this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, display ? 0 : wxTE_PASSWORD);
		newTextCtrl->SetMaxLength (VolumePassword::MaxSize); 
		newTextCtrl->SetValue ((*textCtrl)->GetValue());
		newTextCtrl->SetMinSize ((*textCtrl)->GetSize());

		GridBagSizer->Detach ((*textCtrl));
		GridBagSizer->Add (newTextCtrl, wxGBPosition (row, 1), wxGBSpan (1, 2), wxEXPAND|wxBOTTOM|wxALIGN_CENTER_VERTICAL, 5);
		(*textCtrl)->Show (false);
		WipeTextCtrl (*textCtrl);

		Fit();
		Layout();
		newTextCtrl->SetMinSize ((*textCtrl)->GetMinSize());

		newTextCtrl->Connect (wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler (VolumePasswordPanel::OnTextChanged), nullptr, this);
		*textCtrl = newTextCtrl;
	}

	shared_ptr <VolumePassword> VolumePasswordPanel::GetPassword () const
	{
        return GetPassword (PasswordTextCtrl, DaPlugFound); /*[XaV] initial return GetPassword (PasswordTextCtrl); */
	}

	shared_ptr <VolumePassword> VolumePasswordPanel::GetPassword (wxTextCtrl *textCtrl) const
	{
		shared_ptr <VolumePassword> password;
		wchar_t passwordBuf[VolumePassword::MaxSize + 1];
		finally_do_arg (BufferPtr, BufferPtr (reinterpret_cast <byte *> (passwordBuf), sizeof (passwordBuf)), { finally_arg.Erase(); });

#ifdef TC_WINDOWS
		int len = GetWindowText (static_cast <HWND> (textCtrl->GetHandle()), passwordBuf, VolumePassword::MaxSize + 1);
		password.reset (new VolumePassword (passwordBuf, len));
#else
		wxString passwordStr (textCtrl->GetValue());	// A copy of the password is created here by wxWidgets, which cannot be erased
		for (size_t i = 0; i < passwordStr.size() && i < VolumePassword::MaxSize; ++i)
		{
			passwordBuf[i] = (wchar_t) passwordStr[i];
			passwordStr[i] = L'X';
		}
		password.reset (new VolumePassword (passwordBuf, passwordStr.size() <= VolumePassword::MaxSize ? passwordStr.size() : VolumePassword::MaxSize));
#endif
		return password;
	}

    shared_ptr <VolumePassword> VolumePasswordPanel::GetPassword (wxTextCtrl *textCtrl, bool secondFactor) const /*[XaV]*/
    {
        shared_ptr <VolumePassword> password;
        wchar_t passwordBuf[VolumePassword::MaxSize + 1];
        finally_do_arg (BufferPtr, BufferPtr (reinterpret_cast <byte *> (passwordBuf), sizeof (passwordBuf)), { finally_arg.Erase(); });

#ifdef TC_WINDOWS // Does not use the DaPlug
        int len = GetWindowText (static_cast <HWND> (textCtrl->GetHandle()), passwordBuf, VolumePassword::MaxSize + 1);
        password.reset (new VolumePassword (passwordBuf, len));
#else
        wxString passwordStr (textCtrl->GetValue());	// A copy of the password is created here by wxWidgets, which cannot be erased
        size_t password_s = passwordStr.size();
        size_t DaPlugPassword_s = 0;
        if (secondFactor)
            DaPlugPassword_s = wcslen(DaPlugPassword);
        size_t cumulative_s = password_s + DaPlugPassword_s;

        for (size_t i = 0; i < password_s && i < VolumePassword::MaxSize; ++i)
        {
            passwordBuf[i] = (wchar_t) passwordStr[i];
            passwordStr[i] = L'X';
        }
        for (size_t j = password_s; j < cumulative_s && j < VolumePassword::MaxSize; ++j)
        {
            passwordBuf[j] = DaPlugPassword[j-password_s]; //TODO: error !
        }
        password.reset (new VolumePassword (passwordBuf, cumulative_s <= VolumePassword::MaxSize ? cumulative_s : VolumePassword::MaxSize));
#endif
        fprintf(stderr,"\nUse the DaPlug as second factor? = %d\n",secondFactor);
        return password;
    }

	shared_ptr <Pkcs5Kdf> VolumePasswordPanel::GetPkcs5Kdf () const
	{
		try
		{
			return Pkcs5Kdf::GetAlgorithm (wstring (Pkcs5PrfChoice->GetStringSelection()));
		}
		catch (ParameterIncorrect&)
		{
			return shared_ptr <Pkcs5Kdf> ();
		}
	}

	void VolumePasswordPanel::OnAddKeyfileDirMenuItemSelected (wxCommandEvent& event)
	{
		try
		{
			DirectoryPath dir = Gui->SelectDirectory (this, LangString["SELECT_KEYFILE_PATH"]);

			if (!dir.IsEmpty())
			{
				Keyfiles->push_back (make_shared <Keyfile> (dir));

				UseKeyfilesCheckBox->SetValue (!Keyfiles->empty());
				OnUpdate();
			}
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void VolumePasswordPanel::OnAddKeyfilesMenuItemSelected (wxCommandEvent& event)
	{
		try
		{
			FilePathList files = Gui->SelectFiles (this, LangString["SELECT_KEYFILES"], false, true);

			if (!files.empty())
			{
				foreach_ref (const FilePath &f, files)
					Keyfiles->push_back (make_shared <Keyfile> (f));

				UseKeyfilesCheckBox->SetValue (!Keyfiles->empty());
				OnUpdate();
			}
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void VolumePasswordPanel::OnAddSecurityTokenSignatureMenuItemSelected (wxCommandEvent& event)
	{
		try
		{
			SecurityTokenKeyfilesDialog dialog (this);
			if (dialog.ShowModal() == wxID_OK)
			{
				foreach (const SecurityTokenKeyfilePath &path, dialog.GetSelectedSecurityTokenKeyfilePaths())
				{
					Keyfiles->push_back (make_shared <Keyfile> (wstring (path)));
				}

				if (!dialog.GetSelectedSecurityTokenKeyfilePaths().empty())
				{
					UseKeyfilesCheckBox->SetValue (!Keyfiles->empty());
					OnUpdate();
				}
			}
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}
	}

	void VolumePasswordPanel::OnDisplayPasswordCheckBoxClick (wxCommandEvent& event)
	{
		DisplayPassword (event.IsChecked(), &PasswordTextCtrl, 1);
		
		if (ConfirmPasswordTextCtrl->IsShown())
			DisplayPassword (event.IsChecked(), &ConfirmPasswordTextCtrl, 2);

		OnUpdate();
	}

	void VolumePasswordPanel::OnKeyfilesButtonClick (wxCommandEvent& event)
	{
		KeyfilesDialog dialog (GetParent(), Keyfiles);

        if (dialog.ShowModal() == wxID_OK)
		{
			Keyfiles = dialog.GetKeyfiles();

			UseKeyfilesCheckBox->SetValue (!Keyfiles->empty());
			OnUpdate();
        }
	}

    bool CheckEmptyPassword (wxString password) /*[XaV]*/
    {
        size_t password_s = password.size();
        return (password_s == 0);
    }

    void VolumePasswordPanel::OnDaPlugButtonClick (wxCommandEvent& event) /*[XaV]*/
    {
        fprintf(stderr,"\nVerification passwords match? %d\n",needConfirmation);
        bool matchPwd = true;
        if (needConfirmation)
            matchPwd = PasswordsMatch();
        fprintf(stderr,"\nVerification passwords match = %d\n",matchPwd);

        fprintf(stderr,"\nVerification passwords is empty? %d\n",1);
        bool emptyPwd = CheckEmptyPassword (PasswordTextCtrl->GetValue());
        fprintf(stderr,"\nVerification passwords is empty = %d\n",emptyPwd);

        if (matchPwd)
            DaPlugFound = InitializeDaPlug();

        DaPlugDialog dialog (GetParent()/*, Keyfiles*/, DaPlugFound, matchPwd, emptyPwd);
        dialog.ShowModal();
        UseDaPlugCheckBox->SetValue(DaPlugFound);
        OnUpdate();
    }

	void VolumePasswordPanel::OnKeyfilesButtonRightClick (wxMouseEvent& event)
	{
		wxMenu popup;
		Gui->AppendToMenu (popup, LangString["IDC_KEYADD"], this, wxCommandEventHandler (VolumePasswordPanel::OnAddKeyfilesMenuItemSelected));
		Gui->AppendToMenu (popup, LangString["IDC_ADD_KEYFILE_PATH"], this, wxCommandEventHandler (VolumePasswordPanel::OnAddKeyfileDirMenuItemSelected));
		Gui->AppendToMenu (popup, LangString["IDC_TOKEN_FILES_ADD"], this, wxCommandEventHandler (VolumePasswordPanel::OnAddSecurityTokenSignatureMenuItemSelected));

		PopupMenu (&popup, KeyfilesButton->GetPosition().x + 2, KeyfilesButton->GetPosition().y + 2);
	}

	void VolumePasswordPanel::OnKeyfilesButtonRightDown (wxMouseEvent& event)
	{
#ifndef TC_MACOSX
		event.Skip();
#endif
	}

    void VolumePasswordPanel::OnUseDaPlugCheckBoxClick (wxCommandEvent& event)
    {
        DaPlugFound = false;
        // Cannot do DaPlugFound = true, will check concatened password ==> out of range
        UseDaPlugCheckBox->SetValue(DaPlugFound);
        OnUpdate();
    }

	bool VolumePasswordPanel::PasswordsMatch () const
	{
		assert (ConfirmPasswordStaticText->IsShown());
		return *GetPassword (PasswordTextCtrl) == *GetPassword (ConfirmPasswordTextCtrl);
	}

	void VolumePasswordPanel::WipeTextCtrl (wxTextCtrl *textCtrl)
	{
		textCtrl->SetValue (wxString (L'X', textCtrl->GetLineLength(0)));
		GetPassword (textCtrl);
	}



    /* DaPlug Functions */
    void CheckDaPlugMode (Dongle_info *d)
    {
        if (d->type == 0)
            fprintf(stderr,"\nA HID dongle is found.\n");
        if (d->type == 1)
            fprintf(stderr,"\nAn USB dongle is found.\n");
    }

    bool VolumePasswordPanel::InitializeDaPlug () /*XaV*/
    {
        int nb_dongles = 0;
        Dongle_info dongles[CON_DNG_MAX_NB];
        nb_dongles = Daplug_getDongleList(dongles);

        bool found = false;
        if (nb_dongles > 0)
        {
            //Select the first dongle and check it
            DaplugDongle dpd;
            Dongle_info *d = &dongles[0];
            if (d->type == 0 || d->type == 1)
            {
                Daplug_getDongleById(d,&dpd);
                //found = true;

                //Display mode
                CheckDaPlugMode(d);

                //Get serial number as second factor
                char sn[0x12*2+1]="";
                if(Daplug_getDongleSerial(&dpd,sn))
                {
                    fprintf(stderr,"\nSerial Number = %s\n",sn);
                    const size_t snSize = strlen(sn)+1;
                    DaPlugPassword = new wchar_t[snSize];
                    mbstowcs (DaPlugPassword, sn, snSize);
                    fprintf(stderr,"\nSerial Number added to TrueCrypt\n");
                    found = true;
                 }

            }
            else
                fprintf(stderr,"\nError, neither a HID dongle nor an USB one.\n");

            //Free memory
            Daplug_free(&dpd, dongles, nb_dongles);
            Daplug_exit();
        }
        return found;
    }


}
