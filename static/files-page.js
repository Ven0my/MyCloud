function slugify(name){
return name.replace(' ', '-').replace('*', '-').replace('+', '-')};

$('.btn-share-file').on('click', function() {
    const $this = $(this);
    $('#shareModal').modal();
    console.log('Modal is now shown');

    const fileId = $this.attr('data-file-id');
    const fileName = $this.attr('data-file-name');
    const fileNameSlugified = slugify(fileName);

    const permalink = 'http://localhost:5000' + '/download/' + fileId + '/' + fileNameSlugified;   //later concatenate fileNameSlugified
    console.log(permalink);

    $('#shareModal .share-link').html(permalink);

});