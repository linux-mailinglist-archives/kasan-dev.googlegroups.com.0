Return-Path: <kasan-dev+bncBCMIZB7QWENRBWNLWSNAMGQEAWQD3SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id E646C6008F2
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 10:44:09 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id g27-20020adfa49b000000b0022cd5476cc7sf3456477wrb.17
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 01:44:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665996249; cv=pass;
        d=google.com; s=arc-20160816;
        b=OOo/yzcljdgw9mtphvfvRpVMsKh4YHDUpFH4qB8N9N93C++sP4CZZ6mr1izBS2Sa7i
         Lar6UQ7DJRuTEkNFtLfcdJZaPMwMU2Z2KCbrEZoCY8bQ9W1xaLQjk/Ya5hweE4027waN
         wIqLE1v9CfkVftpLz5PvyHp7o9GpRyFByv7G22tRfB/BKokVe53GXIkAUkyLCzDsR/WU
         Sw0ThcOxAbKwEfn7GPZzwIrAfS2JaPcbRAhsjTG9LzqcsESbVQq0CGtlg3ACwAwg/TMu
         8XnRngepL/MntEjfV6iZMlWBu8K5VRHwn3ralFTXdZUIergV5DwttXGz2SZ9VHskCbIb
         M/fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=v7KV8bMpZUlf6NTkaT+2vYrlo+o4HBQniniVYMHnn6g=;
        b=G0h4yTlKwtOxol4CWae80b+BR2+7Mwc0AeWRgdJpNCtYXyhF0l8kt/Ufkr5pkg/pQN
         TMz0xC1GWxiI3ow4KzcNkdvQ6KzuxjP1Ae9mNDi36DYVn4iQ5BTDkJmfw4MzYigBZuIc
         NAZi3I8v+YPo6wFwrqqF1K6sLLna1QgyNNTfPJxF2l7dFLVm6Zz3IfLh1a/h5ZVBZgE7
         k88PbWliGTuaoSn16XFm/g9MaiD/G61lGKSbRM6Wu94Are4L43n9jKv1+QRs51WmdfcS
         aWQ4DGpkQViPgX5yLtXr1df/Sk+Yf0dx95md1YXkgo6TSlO0Us1AOyroDoeE4I+QN+qq
         xi9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Nrfotfa7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=v7KV8bMpZUlf6NTkaT+2vYrlo+o4HBQniniVYMHnn6g=;
        b=WJnfgIbeKZScLhyeFL8T64FPVq4dKV03cYKESTbVjDucfJUjdXSR/776z6SEd9hn1e
         uUqDPiN+lSgCwyCxbEnzWGB8MeNOaS75ISqvVETC4RGKkO9p6cUqUTrF+2GAkvPhq4dI
         ixlOka3bOjhIdC2Yz8uqScS/jxLiRRyEkz9CtNGqcvwxq7CjPw3wqqcAKKMxzoS5jYqN
         RNy3WjKwAZgl66UDhRB6QURH6yi4AjCh+HLqmqKZBukYJePUNyIcSqtFjIM6kVDRM5Lz
         qQaV6oYl04Y3S2JVXJ2IBe/ppmUCymAymRWtiEP2UK+uPNXYL3PImNPD8dGM9sV46utB
         jnOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=v7KV8bMpZUlf6NTkaT+2vYrlo+o4HBQniniVYMHnn6g=;
        b=qYKnr5g9FV3/e8MbWkXVEr2KexiAKkAWDaHniZoESk6/tVJ2GRiUzJN6YuYnxg5tIs
         cwc9AEbqxJRaAz18fuAm1laTDASw6dXgcLSQab0WiimixgDS9+njGlysIwNpWpSbNk6c
         M5cOncWFabiLHWOntXu4IRR0+Law/N17WaZaubWe/ItpnJR/h8MTbqDgaU8L6APKXGyd
         GRHFHuv4zJLo7EV/M5MaYS9QqQGrLFLJOH6KAF753tBoeNpzuBaUYo53CSMUdmkL6A14
         cGHKG0L0u8z7UdD3sYEhEW5xFbdNBtNGdFXfrf5aNBBCCs2SIlLQPZNszjk4Me4oICBp
         0Mwg==
X-Gm-Message-State: ACrzQf0ToID2O8nlO/Eo8T2bs9tpk9an3M+eWw66ec6X/mR7UGGHhwp7
	bEiBPfQIMqXgr6qypUuBRXY=
X-Google-Smtp-Source: AMsMyM48OH+jb+Ah2O60Xmvh43rQqFKnyWLVyQt42W0MXCQKnLm9rDHGbEoSewMHgePonembA73ZBA==
X-Received: by 2002:a05:600c:3b88:b0:3c6:cef8:8465 with SMTP id n8-20020a05600c3b8800b003c6cef88465mr18104437wms.64.1665996249474;
        Mon, 17 Oct 2022 01:44:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c458:0:b0:3c6:c1ff:1fd with SMTP id l24-20020a7bc458000000b003c6c1ff01fdls7438373wmi.2.-pod-canary-gmail;
 Mon, 17 Oct 2022 01:44:08 -0700 (PDT)
X-Received: by 2002:a05:600c:3b22:b0:3c3:e25:f9e with SMTP id m34-20020a05600c3b2200b003c30e250f9emr6530040wms.183.1665996248293;
        Mon, 17 Oct 2022 01:44:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665996248; cv=none;
        d=google.com; s=arc-20160816;
        b=rMOKYkkbNJmE6jgx1WDmLAZ5AW6m7B6i2FEjC2fDmKpc89/oRxXEbjgTFxdM8rYm6S
         04RI9nMKRA2x3rRtApdE3qT/ZZeKlnncMLlJ19+76XQnHNk5FUIOn7WHULAwXsYzUKJB
         yiwBE8GSV8It0pGCTrHTdqkMZM32o/SKTPDz8e78Cf9eWYomwv4PDFEHi/I1X/hthHHb
         JavVZDM5RWt9GAQ5cUTcyN6Lc4t50SxMHEUkQfsIn3e21C+XmOWT4RkX5dOe2dziqWW7
         G25s18XDJO5hO62cwTP0QpMvMNVXe4pCBCzp2oUJZ6eAPmo50P0Yf4hgjoPDPETotKH4
         3qkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qwIwAcqWBfBMRrm9KF2boeBuiPaxpIOUZ43XencQIbo=;
        b=O1vjZojKqXXTh1j43CDaNa0XfTr4Lb9UaE+UeScV5Z8yKWaTYLDsDaA0DJxPZv07qM
         UbS1/IXaPF3qUXnrB8p4gi1u/nqDEuYw0JUsUuR8wbzfxtrMV8Vxc8V0ABC+bJjUTWxD
         nh6snL90OJNl9rHmO9TcWMzrR8AmWvdttO0nn0Hor2lPuyVXvCqH7TFRWlliQHmQUHEx
         jDxzQOuDoad9ra54r0etkTuSSLJc0TpDbXBdz/dzsf7NQZnQmPe11hRmjb922CkSFBP4
         Q+uyuuOJLgiMYK43abhXucyg55bsQVmLBTkMdIvqTq2rWpeZo3J8QUkxamGcUO0WqPAO
         AQfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Nrfotfa7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id co22-20020a0560000a1600b0022e5cd5f848si355035wrb.3.2022.10.17.01.44.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Oct 2022 01:44:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id r22so13067242ljn.10
        for <kasan-dev@googlegroups.com>; Mon, 17 Oct 2022 01:44:08 -0700 (PDT)
X-Received: by 2002:a2e:b5af:0:b0:26f:d634:2f0d with SMTP id
 f15-20020a2eb5af000000b0026fd6342f0dmr3852031ljn.33.1665996247476; Mon, 17
 Oct 2022 01:44:07 -0700 (PDT)
MIME-Version: 1.0
References: <20221014084837.1787196-1-hrkanabar@gmail.com> <20221014084837.1787196-4-hrkanabar@gmail.com>
 <5bc906b3-ccb5-a385-fcb6-fc51c8fea3fd@suse.com>
In-Reply-To: <5bc906b3-ccb5-a385-fcb6-fc51c8fea3fd@suse.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 Oct 2022 10:43:55 +0200
Message-ID: <CACT4Y+YeSOZPN+ek6vSLhsCugJ3iGF35-sghnZt4qQJ36DA6mA@mail.gmail.com>
Subject: Re: [PATCH RFC 3/7] fs/btrfs: support `DISABLE_FS_CSUM_VERIFICATION`
 config option
To: Qu Wenruo <wqu@suse.com>
Cc: Hrutvik Kanabar <hrkanabar@gmail.com>, Hrutvik Kanabar <hrutvik@google.com>, 
	Marco Elver <elver@google.com>, Aleksandr Nogikh <nogikh@google.com>, kasan-dev@googlegroups.com, 
	Alexander Viro <viro@zeniv.linux.org.uk>, linux-fsdevel@vger.kernel.org, 
	linux-kernel@vger.kernel.org, "Theodore Ts'o" <tytso@mit.edu>, 
	Andreas Dilger <adilger.kernel@dilger.ca>, linux-ext4@vger.kernel.org, 
	Chris Mason <clm@fb.com>, Josef Bacik <josef@toxicpanda.com>, David Sterba <dsterba@suse.com>, 
	linux-btrfs@vger.kernel.org, Jaegeuk Kim <jaegeuk@kernel.org>, Chao Yu <chao@kernel.org>, 
	linux-f2fs-devel@lists.sourceforge.net, 
	"Darrick J . Wong" <djwong@kernel.org>, linux-xfs@vger.kernel.org, 
	Namjae Jeon <linkinjeon@kernel.org>, Sungjong Seo <sj1557.seo@samsung.com>, 
	Anton Altaparmakov <anton@tuxera.com>, linux-ntfs-dev@lists.sourceforge.net
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Nrfotfa7;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Fri, 14 Oct 2022 at 12:24, 'Qu Wenruo' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On 2022/10/14 16:48, Hrutvik Kanabar wrote:
> > From: Hrutvik Kanabar <hrutvik@google.com>
> >
> > When `DISABLE_FS_CSUM_VERIFICATION` is enabled, bypass checksum
> > verification.
> >
> > Signed-off-by: Hrutvik Kanabar <hrutvik@google.com>
>
> I always want more fuzz for btrfs, so overall this is pretty good.
>
> But there are some comments related to free space cache part.
>
> Despite the details, I'm wondering would it be possible for your fuzzing
> tool to do a better job at user space? Other than relying on loosen
> checks from kernel?
>
> For example, implement a (mostly) read-only tool to do the following
> workload:
>
> - Open the fs
>    Including understand the checksum algo, how to re-generate the csum.
>
> - Read out the used space bitmap
>    In btrfs case, it's going to read the extent tree, process the
>    backrefs items.
>
> - Choose the victim sectors and corrupt them
>    Obviously, vitims should be choosen from above used space bitmap.
>
> - Re-calculate the checksum for above corrupted sectors
>    For btrfs, if it's a corrupted metadata, re-calculate the checksum.
>
> By this, we can avoid such change to kernel, and still get a much better
> coverage.
>
> If you need some help on such user space tool, I'm pretty happy to
> provide help.
>
> > ---
> >   fs/btrfs/check-integrity.c  | 3 ++-
> >   fs/btrfs/disk-io.c          | 6 ++++--
> >   fs/btrfs/free-space-cache.c | 3 ++-
> >   fs/btrfs/inode.c            | 3 ++-
> >   fs/btrfs/scrub.c            | 9 ++++++---
> >   5 files changed, 16 insertions(+), 8 deletions(-)
> >
> > diff --git a/fs/btrfs/check-integrity.c b/fs/btrfs/check-integrity.c
> > index 98c6e5feab19..eab82593a325 100644
> > --- a/fs/btrfs/check-integrity.c
> > +++ b/fs/btrfs/check-integrity.c
> > @@ -1671,7 +1671,8 @@ static noinline_for_stack int btrfsic_test_for_metadata(
> >               crypto_shash_update(shash, data, sublen);
> >       }
> >       crypto_shash_final(shash, csum);
> > -     if (memcmp(csum, h->csum, fs_info->csum_size))
> > +     if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
> > +         memcmp(csum, h->csum, fs_info->csum_size))
> >               return 1;
> >
> >       return 0; /* is metadata */
> > diff --git a/fs/btrfs/disk-io.c b/fs/btrfs/disk-io.c
> > index a2da9313c694..7cd909d44b24 100644
> > --- a/fs/btrfs/disk-io.c
> > +++ b/fs/btrfs/disk-io.c
> > @@ -184,7 +184,8 @@ static int btrfs_check_super_csum(struct btrfs_fs_info *fs_info,
> >       crypto_shash_digest(shash, raw_disk_sb + BTRFS_CSUM_SIZE,
> >                           BTRFS_SUPER_INFO_SIZE - BTRFS_CSUM_SIZE, result);
> >
> > -     if (memcmp(disk_sb->csum, result, fs_info->csum_size))
> > +     if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
> > +         memcmp(disk_sb->csum, result, fs_info->csum_size))
> >               return 1;
> >
> >       return 0;
> > @@ -494,7 +495,8 @@ static int validate_extent_buffer(struct extent_buffer *eb)
> >       header_csum = page_address(eb->pages[0]) +
> >               get_eb_offset_in_page(eb, offsetof(struct btrfs_header, csum));
> >
> > -     if (memcmp(result, header_csum, csum_size) != 0) {
> > +     if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
> > +         memcmp(result, header_csum, csum_size) != 0) {
>
> I believe this is the main thing fuzzing would take advantage of.
>
> It would be much better if this is the only override...
>
> >               btrfs_warn_rl(fs_info,
> >   "checksum verify failed on logical %llu mirror %u wanted " CSUM_FMT " found " CSUM_FMT " level %d",
> >                             eb->start, eb->read_mirror,
> > diff --git a/fs/btrfs/free-space-cache.c b/fs/btrfs/free-space-cache.c
> > index f4023651dd68..203c8a9076a6 100644
> > --- a/fs/btrfs/free-space-cache.c
> > +++ b/fs/btrfs/free-space-cache.c
> > @@ -574,7 +574,8 @@ static int io_ctl_check_crc(struct btrfs_io_ctl *io_ctl, int index)
> >       io_ctl_map_page(io_ctl, 0);
> >       crc = btrfs_crc32c(crc, io_ctl->orig + offset, PAGE_SIZE - offset);
> >       btrfs_crc32c_final(crc, (u8 *)&crc);
> > -     if (val != crc) {
> > +     if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
> > +         val != crc) {
>
> I'm already seeing this to cause problems, especially for btrfs.
>
> Btrfs has a very strong dependency on free space tracing, as all of our
> metadata (and data by default) relies on COW to keep the fs consistent.
>
> I tried a lot of different methods in the past to make sure we won't
> write into previously used space, but it's causing a lot of performance
> impact.
>
> Unlike tree-checker, we can not easily got a centerlized space to handle
> all the free space cross-check thing (thus it's only verified by things
> like btrfs-check).
>
> Furthermore, even if you skip this override, with latest default
> free-space-tree feature, free space info is stored in regular btrfs
> metadata (tree blocks), with regular metadata checksum protection.
>
> Thus I'm pretty sure we will have tons of reports on this, and
> unfortunately we can only go whac-a-mole way for it.

Hi Qu,

I don't fully understand what you mean. Could you please elaborate?

Do you mean that btrfs uses this checksum check to detect blocks that
were written to w/o updating the checksum?




> >               btrfs_err_rl(io_ctl->fs_info,
> >                       "csum mismatch on free space cache");
> >               io_ctl_unmap_page(io_ctl);
> > diff --git a/fs/btrfs/inode.c b/fs/btrfs/inode.c
> > index b0807c59e321..1a49d897b5c1 100644
> > --- a/fs/btrfs/inode.c
> > +++ b/fs/btrfs/inode.c
> > @@ -3434,7 +3434,8 @@ int btrfs_check_sector_csum(struct btrfs_fs_info *fs_info, struct page *page,
> >       crypto_shash_digest(shash, kaddr, fs_info->sectorsize, csum);
> >       kunmap_local(kaddr);
> >
> > -     if (memcmp(csum, csum_expected, fs_info->csum_size))
> > +     if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
> > +         memcmp(csum, csum_expected, fs_info->csum_size))
>
> This skips data csum check, I don't know how valueable it is, but this
> should be harmless mostly.
>
> If we got reports related to this, it would be a nice surprise.
>
> >               return -EIO;
> >       return 0;
> >   }
> > diff --git a/fs/btrfs/scrub.c b/fs/btrfs/scrub.c
> > index f260c53829e5..a7607b492f47 100644
> > --- a/fs/btrfs/scrub.c
> > +++ b/fs/btrfs/scrub.c
> > @@ -1997,7 +1997,8 @@ static int scrub_checksum_data(struct scrub_block *sblock)
> >
> >       crypto_shash_digest(shash, kaddr, fs_info->sectorsize, csum);
> >
> > -     if (memcmp(csum, sector->csum, fs_info->csum_size))
> > +     if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
> > +         memcmp(csum, sector->csum, fs_info->csum_size))
>
> Same as data csum verification overide.
> Not necessary/useful but good to have.
>
> >               sblock->checksum_error = 1;
> >       return sblock->checksum_error;
> >   }
> > @@ -2062,7 +2063,8 @@ static int scrub_checksum_tree_block(struct scrub_block *sblock)
> >       }
> >
> >       crypto_shash_final(shash, calculated_csum);
> > -     if (memcmp(calculated_csum, on_disk_csum, sctx->fs_info->csum_size))
> > +     if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
> > +         memcmp(calculated_csum, on_disk_csum, sctx->fs_info->csum_size))
>
> This is much less valueable, since it's only affecting scrub, and scrub
> itself is already very little checking the content of metadata.

Could you please elaborate here as well?
This is less valuable from what perspective?
The data loaded from disk can have any combination of
(correct/incorrect metadata) x (correct/incorrect checksum).
Correctness of metadata and checksum are effectively orthogonal,
right?



> Thanks,
> Qu
>
> >               sblock->checksum_error = 1;
> >
> >       return sblock->header_error || sblock->checksum_error;
> > @@ -2099,7 +2101,8 @@ static int scrub_checksum_super(struct scrub_block *sblock)
> >       crypto_shash_digest(shash, kaddr + BTRFS_CSUM_SIZE,
> >                       BTRFS_SUPER_INFO_SIZE - BTRFS_CSUM_SIZE, calculated_csum);
> >
> > -     if (memcmp(calculated_csum, s->csum, sctx->fs_info->csum_size))
> > +     if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
> > +         memcmp(calculated_csum, s->csum, sctx->fs_info->csum_size))
> >               ++fail_cor;
> >
> >       return fail_cor + fail_gen;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYeSOZPN%2Bek6vSLhsCugJ3iGF35-sghnZt4qQJ36DA6mA%40mail.gmail.com.
