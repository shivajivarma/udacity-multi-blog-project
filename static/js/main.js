(function ($) {
    $(function () {

        var wow = new WOW();
        wow.init();

        $('.triggerModal').on('click', function(e){
            e.preventDefault();
            var target = $(this).attr('data-target');

            $(target).modal('show');

        });
  
    }); // end of document ready
})(jQuery); // end of jQuery name space