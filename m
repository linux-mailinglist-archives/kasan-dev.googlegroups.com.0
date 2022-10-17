Return-Path: <kasan-dev+bncBCMIZB7QWENRBPNGWSNAMGQEDNCRSUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id CF33B6008BE
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 10:33:02 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id v10-20020a19740a000000b004a23e7880efsf3376109lfe.8
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 01:33:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665995582; cv=pass;
        d=google.com; s=arc-20160816;
        b=BSQ+3n12wee1HBIvfn+OI+TttK9ah44F8yX5nzk13luP3B9exczDR3gaB5AtyKyFQk
         9oudhicxHV4LlI5iDDTS+6Zk1tgAeWfUQxAC7XcgwdFm0bPq/5Vl2W4KSvAI9KclPY3z
         gGLGP235clz9Ari2bU8TKnCcg1hBgB5E6FY/oULC5ArFlhKP4bfV1ds4OXY78LxWcY3d
         pS78W33Joy9RVoAxV3lgRd0qPch7xOfxXjJ1MJMUwxZyOCdF8xc8I7Cc/7FyP2dC0UeC
         nHfzEzg8welTucvxWIjhTvnYRAW67zm1+m5kX440SJk6l0yNqhCVE+TvMJfGwsZhcGHX
         EEeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HMqPsvxTfKRKibP0HMdc4nNDxNo3OzSDT/58jFnxc9g=;
        b=nT7pNeO69KhoHZ0oJD4IxyJgKs0262T9/uqHz8X5yXrUngdPk1n8OxTLwOwaGukB6t
         tMiNkahgR4qVaZpJuyGcNkuZWgyyDjj8e0Lb5npOn2a3Vn+sfY+l7KsZkthtl03Qqj+l
         gWisxObhuisOYUusoEwfKr65jlkv9F8oOS1r9rM0HfIaULqqXE1u+GsI3fvhDkaX/4d8
         sl8P3UQSvx62fdwtMRVYZZ7bv/aHeWQUDIlODjeIe9QrD0c5uqrnM5BAAbbzZiG6CaBy
         RUlF/X0u69L6YZrvXCPuot9cjKVVu+63CNRaGW6glXQVUgA8UG05dKhrwl+jz9oowFKI
         2kOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="a/oDAz3x";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HMqPsvxTfKRKibP0HMdc4nNDxNo3OzSDT/58jFnxc9g=;
        b=D2TJ/Y09JJtecxPKqrz8ov5YDOpoxRytjqR0DaOA+3Samr5zJ/scXs7yyavPX+oaEC
         4wwtym5i8OrZXxCtkJehHffv2Va6wu+zBrcETwrMtTVYGOjBDruvfpCpohSF5nFxUQ6U
         l+LF08H84ZHCmKERGXy6PGhPzhwsll2jLW/bZNzOIl5fHJm2wpn+FwG15z2lDFvCa5WO
         WaWFTPptZOPl5hoK9zvamtpx41enev/VH7yX/FIzx8tiwMmF0GOWqdDRDdjwQuzUPQDp
         lxz1LARWm8m0Se/nQCKdMVhV9jBndQ2Ch7mJfQdIUQWADRIo0tZxORbh9SVy7/4Kg/M5
         Bppg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=HMqPsvxTfKRKibP0HMdc4nNDxNo3OzSDT/58jFnxc9g=;
        b=hZspJkLCt8cKqtUtYzVma14X0HwKy3JhhLjJOjJvCKM9aeboq9VHSmLsJM+4JO2mfo
         zZpQYgMi4uzzmRE2CAU5UX+rrhLqCrdlGLgepR53cwYIzisZPmTZCLmRMLmnPeRm/cZz
         E/4q9KwHNa4yXqkUL/lm4Z2SPk8Pv5HvYVoKqhCVjE+PCQL9R/Ghidl376QjHeIgsFrI
         GleW2B5r4dcQXKrEhSuVBDNeDHeoXm6QqAcuHBX73ZJdTaUw7enVx/McAtk6eKjEffKp
         QhRW7dmrJm7cMIIgaBFRcmSc0VseTQO4eKs6Y/fvyP3tFM2TP20dT9svcZPGmN9Gk4zB
         hQ3Q==
X-Gm-Message-State: ACrzQf0nBoKO8HCDFB74GEVgAkwbixT50w6AcZMBD19qZsIM2BAPgG3L
	fyY6acnDOpYOdPLA8qHgOXc=
X-Google-Smtp-Source: AMsMyM4qkPgLCWjG7uSb8YYv96j0jGCbRDaXyJZ1kRkMFJKZBaKO3WP0LbhEsjryzAR8zqY2TxeV0g==
X-Received: by 2002:a2e:bd0e:0:b0:268:c03b:cf56 with SMTP id n14-20020a2ebd0e000000b00268c03bcf56mr3810958ljq.393.1665995582001;
        Mon, 17 Oct 2022 01:33:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1ca:b0:26f:c18d:361f with SMTP id
 d10-20020a05651c01ca00b0026fc18d361fls1969602ljn.2.-pod-prod-gmail; Mon, 17
 Oct 2022 01:33:00 -0700 (PDT)
X-Received: by 2002:a2e:bc24:0:b0:26f:a6f1:e8ca with SMTP id b36-20020a2ebc24000000b0026fa6f1e8camr3938315ljf.249.1665995580820;
        Mon, 17 Oct 2022 01:33:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665995580; cv=none;
        d=google.com; s=arc-20160816;
        b=oZE1NhHUngWx9psOrbVs3IjTtMMPe/uyFRYrzJOPuk4Kq/Jy/RpTXUo7fMRuczbpls
         O4iNAV+OUL18vk2oDQzi0SUqn1uz86NaZYcy4neLNAj9x9BAHjBiwyV3iw0K3TQXyjl9
         0yNs4lE32DvhjvLINezYYyXTQZumeBuIzevFVMxUzH1tA1mTe0doL/eUvB2cd4DAtdcf
         XNnpekld/gq+zAnLXye3AID5LTP2KLlmAPF7Ld8xwzBrIX7y1scSLTF22Wey5bVI90Tz
         sQxv5MrbkwAGzMaejEd4W8FKZL5tTDICRiftQoqy/Heo28W4b3ccng5F02FNUWs3DqAv
         0N1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=azrjkTSUa/x73/5WnmuPzRdP/HPez6bDQxOpksGkhRA=;
        b=Mo749pGPfCOXr984uW7YMFzMQj/Y9wiUnFZq2tiX/yTrygcookf3/vLT5hvqV8ar8L
         AkR9eXUvESCnPL+wvWY9WRBXm2wix7CjXSgxs5b813V22YLjskRbd3B72OQ3/WLlh4Lu
         3F3t710d/J52TiOtj/K8wbMG9NIKnSJLZKvghbI5FxV6u6xWrBqFw5KsJhKhdVMXsbUS
         ddg7Nu1Qzr25DL7DH2iJBQjgHc/MAPIxrTahEvoZoniwrNS0E/IsUJDSX+sg7zOicAuI
         4QIXxD4dng0ZQWKHXrB6lp4Gpf9BP6tBnyo1fij5iyiOK5nl9vO/t37bsLxj1FVpjmC2
         gV4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="a/oDAz3x";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id f14-20020a056512360e00b0048b12871da5si310045lfs.4.2022.10.17.01.33.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Oct 2022 01:33:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id by36so13069337ljb.4
        for <kasan-dev@googlegroups.com>; Mon, 17 Oct 2022 01:33:00 -0700 (PDT)
X-Received: by 2002:a2e:978e:0:b0:26e:8ad6:6d5b with SMTP id
 y14-20020a2e978e000000b0026e8ad66d5bmr3880239lji.363.1665995580212; Mon, 17
 Oct 2022 01:33:00 -0700 (PDT)
MIME-Version: 1.0
References: <20221014084837.1787196-1-hrkanabar@gmail.com> <20221014084837.1787196-6-hrkanabar@gmail.com>
 <Y0mD0LcNvu+QTlQ9@magnolia>
In-Reply-To: <Y0mD0LcNvu+QTlQ9@magnolia>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 Oct 2022 10:32:48 +0200
Message-ID: <CACT4Y+aNuRX52u5j1vKpJKru-riSktugDMtDKchR0NLCuvXOQg@mail.gmail.com>
Subject: Re: [PATCH RFC 5/7] fs/xfs: support `DISABLE_FS_CSUM_VERIFICATION`
 config option
To: "Darrick J. Wong" <djwong@kernel.org>
Cc: Hrutvik Kanabar <hrkanabar@gmail.com>, Hrutvik Kanabar <hrutvik@google.com>, 
	Marco Elver <elver@google.com>, Aleksandr Nogikh <nogikh@google.com>, kasan-dev@googlegroups.com, 
	Alexander Viro <viro@zeniv.linux.org.uk>, linux-fsdevel@vger.kernel.org, 
	linux-kernel@vger.kernel.org, "Theodore Ts'o" <tytso@mit.edu>, 
	Andreas Dilger <adilger.kernel@dilger.ca>, linux-ext4@vger.kernel.org, 
	Chris Mason <clm@fb.com>, Josef Bacik <josef@toxicpanda.com>, David Sterba <dsterba@suse.com>, 
	linux-btrfs@vger.kernel.org, Jaegeuk Kim <jaegeuk@kernel.org>, Chao Yu <chao@kernel.org>, 
	linux-f2fs-devel@lists.sourceforge.net, linux-xfs@vger.kernel.org, 
	Namjae Jeon <linkinjeon@kernel.org>, Sungjong Seo <sj1557.seo@samsung.com>, 
	Anton Altaparmakov <anton@tuxera.com>, linux-ntfs-dev@lists.sourceforge.net
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="a/oDAz3x";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232
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

On Fri, 14 Oct 2022 at 17:44, Darrick J. Wong <djwong@kernel.org> wrote:
>
> On Fri, Oct 14, 2022 at 08:48:35AM +0000, Hrutvik Kanabar wrote:
> > From: Hrutvik Kanabar <hrutvik@google.com>
> >
> > When `DISABLE_FS_CSUM_VERIFICATION` is enabled, return truthy value for
> > `xfs_verify_cksum`, which is the key function implementing checksum
> > verification for XFS.
> >
> > Signed-off-by: Hrutvik Kanabar <hrutvik@google.com>
>
> NAK, we're not going to break XFS for the sake of automated fuzz tools.

Hi Darrick,

What do you mean by "break"? If this config is not enabled the
behavior is not affected as far as I see.

> You'll have to adapt your fuzzing tools to rewrite the block header
> checksums, like the existing xfs fuzz testing framework does.  See
> the xfs_db 'fuzz -d' command and the relevant fstests.
>
> --D
>
> > ---
> >  fs/xfs/libxfs/xfs_cksum.h | 5 ++++-
> >  1 file changed, 4 insertions(+), 1 deletion(-)
> >
> > diff --git a/fs/xfs/libxfs/xfs_cksum.h b/fs/xfs/libxfs/xfs_cksum.h
> > index 999a290cfd72..ba55b1afa382 100644
> > --- a/fs/xfs/libxfs/xfs_cksum.h
> > +++ b/fs/xfs/libxfs/xfs_cksum.h
> > @@ -76,7 +76,10 @@ xfs_verify_cksum(char *buffer, size_t length, unsigned long cksum_offset)
> >  {
> >       uint32_t crc = xfs_start_cksum_safe(buffer, length, cksum_offset);
> >
> > -     return *(__le32 *)(buffer + cksum_offset) == xfs_end_cksum(crc);
> > +     if (IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION))
> > +             return 1;
> > +     else
> > +             return *(__le32 *)(buffer + cksum_offset) == xfs_end_cksum(crc);
> >  }
> >
> >  #endif /* _XFS_CKSUM_H */
> > --
> > 2.38.0.413.g74048e4d9e-goog
> >
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0mD0LcNvu%2BQTlQ9%40magnolia.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaNuRX52u5j1vKpJKru-riSktugDMtDKchR0NLCuvXOQg%40mail.gmail.com.
