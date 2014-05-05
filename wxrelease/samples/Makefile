#
# Makefile : Builds wxWindows samples for Unix.
#

SAMPLES_SUBDIRS=artprov config console controls dialogs dnd dragimag drawing dynamic erase event except exec font image internat keyboard layout listbox listctrl menu minimal mobile mobile/styles mobile/wxedit notebook propsize render rotate scroll scrollsub shaped statbar taskbar text thread treectrl typetest validate vscroll widgets 

all:
	@for d in $(SAMPLES_SUBDIRS); do (cd $$d && $(MAKE)); done

clean:
	@for d in $(SAMPLES_SUBDIRS); do (cd $$d && $(MAKE) clean); done
