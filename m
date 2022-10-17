Return-Path: <kasan-dev+bncBCMIZB7QWENRBVFFWSNAMGQEH2YWN4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id E76C66008AE
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 10:31:17 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id u12-20020ac248ac000000b004a22e401de1sf3449866lfg.19
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 01:31:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665995477; cv=pass;
        d=google.com; s=arc-20160816;
        b=WEmXJD5rSYz85mDZmZTFt94A6aEiens2PXweNzAAo7eij224oiV1OdJR+RvwMXnMkY
         MbA6ZWTupkF5beBVOl3TKAnDQNwVZ9YAdlGYgo38jZyIMcfNCNkqmSzxipcBTNC7YOmN
         Vg7o9HLOIyMknuglU9brBiguHMvy8ame51C2LPfZj63fcQohvv/xjIhtDuD90yBNzeWB
         1L69fG7nrKf4mvM/icIhXRlWvPy4dSIE9hWIAPmtLoXwya8BwMyYYxDqhELPDm7Y5gTw
         bxfW4vF54XDCXT++j4ZJgJAlFHyhxRo+Z1kXwdYW+ejTFlRPluuypH0YgjCyiCtu3F3Z
         6dRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1+j9ZdoPZXVrlcZPRWU+KyZEu6975E4rn5NbhfXCjz8=;
        b=Cg/jQ9C7VBAKr5X6M0tyL6Ph21C2+AReqbdwiS/hy3d2VchdsA5nbTAZElzkZEyAtb
         9j7IexaOnKdkTLTPBSP91P67IEAYSyd2cznGeJCHt+NBIPG72NuD3Y9Y6LwINfCGWpx6
         gohyumIbIYl4eJVHtN9pxDdH9r3hJUDow5MytRDuDFOsy0gEUzL/LrJIpQihqfHz6zaF
         Ty3iXcCzRwTp3EenDeka1+zU6VLuoT/Q7j86/BzMTZdIo9fSkP5bIpYkIlK58KCcELWx
         Y/6dJty9Au0Bugci3Ho+zpONk8k3lWWcZE1fvU4n5d1SDV2NTcQzYjtR0ssN0aZzWs7z
         qiLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iXrGdd8C;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1+j9ZdoPZXVrlcZPRWU+KyZEu6975E4rn5NbhfXCjz8=;
        b=q+bZcguOIVUzZyBG19K8xC6WP9HI+H+8l8GY4c9pcsldlnL3fcaMeWbs3yImn14GaL
         CUdgHcoBqFPwabdtPZHmvHa4EYtnAQGB/RcEgRUWXQnpxU61sP7IosP3SJxLMP8jMGH/
         B2wt0O1mIYJ9j1QGNt+3oO4qAu+VRB0fUV6XWvsny7nt9HdYVfKr4qmHiLK0LXMNVUxK
         sTDp1NC6nAvs59Ca7d3AEL2tF5ToWgXtvfxOhqceQzCXCQnnJH8hSsf3hqjOOsuO8MHO
         dIflSpjP6OR44XELGMn6wOubviFZeNosRxh3Y97fPPcYfbzCXq0znwWm+Vc7cTv5T+IY
         o32g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=1+j9ZdoPZXVrlcZPRWU+KyZEu6975E4rn5NbhfXCjz8=;
        b=LY2AsshdxCRbMuRVVvanjY5SrkYYFB6wMgg6oQBP2zzbAmnXYczqxZfu8C6Bc9gYSW
         4mP8Em6Lj2U7CA8b69XoayWOhogXsHSp/UeAOxCWgJ02poNJeDl/dIeJOyg18RbkL68W
         ygeJv4FjQj6ZMcYWzpqLEBPEwebz2RZQ5HbIZL68qcChaoe1ozfscXlR6sxxHv6CB5Jf
         wOhzDEd/KijfOMKwi377rL9TGxuxOdZD6sG80rkVi10dWzpL7BONZBCMp7JcUt4A+p2P
         7CfHGOcmSQLPfQRVR2b701nuDyQhrIssTCzTv2ziTKVQk7qAmING1IG2UakMGh1JljaJ
         1Q5Q==
X-Gm-Message-State: ACrzQf0qnXQUdKaSltTwHqeqDgUCRFK3kvVnAl190Q7RlM75ay5h0iJO
	qtojyJGUBumvOzdg4xomIQM=
X-Google-Smtp-Source: AMsMyM49umBc+RYADx+hDVikXFIyQ85Tlyk36sZx5fP7QI9dPfZL3XFeiL3zcxBKyi0yukXw79YIpQ==
X-Received: by 2002:a05:6512:b1e:b0:4a1:ba8c:7ea7 with SMTP id w30-20020a0565120b1e00b004a1ba8c7ea7mr3506843lfu.608.1665995477115;
        Mon, 17 Oct 2022 01:31:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3590:b0:494:6c7d:cf65 with SMTP id
 m16-20020a056512359000b004946c7dcf65ls586323lfr.2.-pod-prod-gmail; Mon, 17
 Oct 2022 01:31:16 -0700 (PDT)
X-Received: by 2002:a05:6512:b9e:b0:4a2:9853:b87f with SMTP id b30-20020a0565120b9e00b004a29853b87fmr3327082lfv.257.1665995475974;
        Mon, 17 Oct 2022 01:31:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665995475; cv=none;
        d=google.com; s=arc-20160816;
        b=Z9X3g/us0Rb7VFiqRKfxH2SxIkhPlTbq513+Of0yZvJUJqMyMQSYHz+3FXkfwSEPmq
         eqe79EPyYsWU0I1kHuX/+L3PvPiDd+OL/q7GKtoP8ajKezDxzIG+kOxDwceIR8g+yF6v
         /IhonNNNV6kIITeSz8PtxBuhp5ddUuXjxfmMMp2yektBaAsuK1ERZ3oX4YKaEMpnCvJx
         3q7YIpL8S94EcVhXf3trGwi9feRpXoLTywaJo5O8lBYbz3g/JhzfiySPzLzi2SYKzdvY
         85/J7MoqFWWAwCyKHFviIFn5anCKt1l0QJ32IRa7pDXfcLfjHk56iIZSvLvIcD5bWugo
         QEGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8KsRspEgB/gOfpXeMit48jsmBa9u2K7sMr+wCGZ90pU=;
        b=DBkdhLhVk49u4LnqBwLvXWZ0S5VRjUKZ8+oa6vrIWBzplhiammwPi173P79TD/1BF1
         SSHo1B/Gy0SfG+8bN0XuXe6VOAxeml/llMMxUcdv16Q2wyPqkbERmvJdjcIDN8Nau+ej
         Y5xS2hBN6DYZIfLF8A39nkKTFpdxvl0ojvVvgAh4szb47X1rnVsnIyH3W0PU31kZXSBC
         KNS0e7THKbOv+Vup6Dg1PSwZ2AKSyMem6VTnvSR34fUv4kvMxNkXbvMy4yhiXfdxsLGU
         BILASJmPxEx8nkGd+ww+CXu2cmExxDK1v0AObuehZwgOi1YF5ekwzJtIkjLLaemj6uA4
         vXUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iXrGdd8C;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12a.google.com (mail-lf1-x12a.google.com. [2a00:1450:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id a25-20020a056512201900b004a1baae2fb1si345057lfb.6.2022.10.17.01.31.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Oct 2022 01:31:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) client-ip=2a00:1450:4864:20::12a;
Received: by mail-lf1-x12a.google.com with SMTP id d6so16344895lfs.10
        for <kasan-dev@googlegroups.com>; Mon, 17 Oct 2022 01:31:15 -0700 (PDT)
X-Received: by 2002:a05:6512:358c:b0:4a2:9c55:c63c with SMTP id
 m12-20020a056512358c00b004a29c55c63cmr3765865lfr.598.1665995475449; Mon, 17
 Oct 2022 01:31:15 -0700 (PDT)
MIME-Version: 1.0
References: <20221014084837.1787196-1-hrkanabar@gmail.com> <20221014091503.GA13389@twin.jikos.cz>
In-Reply-To: <20221014091503.GA13389@twin.jikos.cz>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 Oct 2022 10:31:03 +0200
Message-ID: <CACT4Y+as3SA6C_QFLSeb5JYY30O1oGAh-FVMLCS2NrNahycSoQ@mail.gmail.com>
Subject: Re: [PATCH RFC 0/7] fs: Debug config option to disable filesystem
 checksum verification for fuzzing
To: dsterba@suse.cz
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
 header.i=@google.com header.s=20210112 header.b=iXrGdd8C;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a
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

On Fri, 14 Oct 2022 at 11:15, David Sterba <dsterba@suse.cz> wrote:
>
> On Fri, Oct 14, 2022 at 08:48:30AM +0000, Hrutvik Kanabar wrote:
> > From: Hrutvik Kanabar <hrutvik@google.com>
> >
> > Fuzzing is a proven technique to discover exploitable bugs in the Linux
> > kernel. But fuzzing filesystems is tricky: highly structured disk images
> > use redundant checksums to verify data integrity. Therefore,
> > randomly-mutated images are quickly rejected as corrupt, testing only
> > error-handling code effectively.
> >
> > The Janus [1] and Hydra [2] projects probe filesystem code deeply by
> > correcting checksums after mutation. But their ad-hoc
> > checksum-correcting code supports only a few filesystems, and it is
> > difficult to support new ones - requiring significant duplication of
> > filesystem logic which must also be kept in sync with upstream changes.
> > Corrected checksums cannot be guaranteed to be valid, and reusing this
> > code across different fuzzing frameworks is non-trivial.
> >
> > Instead, this RFC suggests a config option:
> > `DISABLE_FS_CSUM_VERIFICATION`. When it is enabled, all filesystems
> > should bypass redundant checksum verification, proceeding as if
> > checksums are valid. Setting of checksums should be unaffected. Mutated
> > images will no longer be rejected due to invalid checksums, allowing
> > testing of deeper code paths. Though some filesystems implement their
> > own flags to disable some checksums, this option should instead disable
> > all checksums for all filesystems uniformly. Critically, any bugs found
> > remain reproducible on production systems: redundant checksums in
> > mutated images can be fixed up to satisfy verification.
> >
> > The patches below suggest a potential implementation for a few
> > filesystems, though we may have missed some checksums. The option
> > requires `DEBUG_KERNEL` and is not intended for production systems.
> >
> > The first user of the option would be syzbot. We ran preliminary local
> > syzkaller tests to compare behaviour with and without these patches.
> > With the patches, we found a 19% increase in coverage, as well as many
> > new crash types and increases in the total number of crashes:
>
> I think the build-time option inflexible, but I see the point when
> you're testing several filesystems that it's one place to set up the
> environment. Alternatively I suggest to add sysfs knob available in
> debuging builds to enable/disable checksum verification per filesystem.

Hi David,

What usage scenarios do you have in mind for runtime changing of this option?
I see this option intended only for very narrow use cases which
require a specially built kernel in a number of other ways (lots of
which are not tunable at runtime, e.g. debugging configs).

> As this may not fit to other filesystems I don't suggest to do that for
> all but I am willing to do that for btrfs, with eventual extension to
> the config option you propose. The increased fuzzing coverage would be
> good to have.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bas3SA6C_QFLSeb5JYY30O1oGAh-FVMLCS2NrNahycSoQ%40mail.gmail.com.
