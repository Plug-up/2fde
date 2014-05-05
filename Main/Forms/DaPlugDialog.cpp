/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "DaPlugDialog.h"
#include "Main/DaPlug/DaplugDongle.h"

namespace TrueCrypt
{
    DaPlugDialog::DaPlugDialog (wxWindow* parent/*, shared_ptr <KeyfileList> keyfiles*/, bool found, bool pwdMatch, bool pwdEmpty)
        : DaPlugDialogBase (parent)/*, Keyfiles (keyfiles)*/
    {
        /*mKeyfilesPanel = new KeyfilesPanel (this, keyfiles);
        PanelSizer->Add (mKeyfilesPanel, 1, wxALL | wxEXPAND);*/

        //WarningStaticText->SetLabel (LangString["IDT_KEYFILE_WARNING"]);
        if (pwdMatch) {
            if (found) {
                if (pwdEmpty) {
                    WarningStaticText->SetLabel (LangString["IDT_DAPLUG_FOUND_EMPTY"]);
                } else {
                    WarningStaticText->SetLabel (LangString["IDT_DAPLUG_FOUND"]);
                }
            } else {
                WarningStaticText->SetLabel (LangString["IDT_DAPLUG_NOT_FOUND"]);
            }
        } else {
            WarningStaticText->SetLabel (LangString["IDT_DAPLUG_PASSWD_NOT_MATCH"]);
        }

        WarningStaticText->Wrap (Gui->GetCharWidth (this) * 16);

        Layout();
        Fit();

        /*KeyfilesNoteStaticText->SetLabel (LangString["KEYFILES_NOTE"]);
        KeyfilesNoteStaticText->Wrap (UpperSizer->GetSize().GetWidth() - Gui->GetCharWidth (this) * 2);*/

        Layout();
        Fit();
        Center();
    }

    /*void KeyfilesDialog::OnCreateKeyfileButttonClick (wxCommandEvent& event)
    {
        Gui->CreateKeyfile();
    }

    void KeyfilesDialog::OnKeyfilesHyperlinkClick (wxHyperlinkEvent& event)
    {
        Gui->OpenHomepageLink (this, L"keyfiles");
    }*/
}

