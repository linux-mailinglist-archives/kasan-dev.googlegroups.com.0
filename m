Return-Path: <kasan-dev+bncBC7OBJGL2MHBBT675OKQMGQEVZ2T5IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 28FE655C0E2
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 14:10:57 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-106a48f2df7sf8357785fac.16
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 05:10:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656418256; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y3bTYtdWdNTxbAedtyP+4HL/BG+aDNbCrjM+BSVBvD1HTrhgCUSESzwX3Ck5PTCpeK
         HCGabEqMI7vRkK2My5h+rDlih7knVS389CpvZkbCC6er+3YNQY1NJB2eRSBf18oXmpIo
         oyzImWo+NqJ477xwqsGPyUPwXn9MnLq/E6DZAd4+Uq4c/TftaXEK1KcW70h2S+OVo7eW
         6vEeZIKeYoBjzET9Fe9OvxZ1i6xdt4RURPJOBdfk/MKudVLBiED0s3gfvJrsiukFPBoc
         qbql6/Ha7y6BfoJtzWwE1E+LaNS27aQWgkOeQ08QLK7ICZfJRoExVc+ks79EHll0+p5d
         wprw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=R7ZP3MarK+ugl8P5WX19zOVhfdMRWuPhBdXyuFEnRFk=;
        b=EL7tVZDTZ3Udp+uefMPIl5m1NEj6DedYt+27/nrx5YBDDwsNrEBD3rqU79r6k7I4Gz
         tFfyUjfhrlGL2OQ5L5CYnsvR4tyMNowy1EFvWnt9Ru9hMy3SFLR8vTTUFgaQ6oSNXELW
         9KJ9CQ8iXdQxzimJRvHgtgTEpVDX+k+K2THPSopXD6l8/31wk85Y3XuE2xaftwMtRUGI
         ltnX7ogPgW9SAZR1v6yfG/GksAEedwh50ONuKMpIK233I1yJnVLfEcL/8Th/pfdnaXCq
         8vIpMImo9ImU7mlUIovGIhKJcLUzVKIWyiw1aGvBiqes/gHwkPmqkyKwrmCI3EoSGJqL
         VUdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CLRflZYy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R7ZP3MarK+ugl8P5WX19zOVhfdMRWuPhBdXyuFEnRFk=;
        b=JcudEOZJoBmI0sp8ppT20H7B6eNk2WigdzZ1pdK4PwFX6aSsQHodXuELGF+lf21B7Z
         WpO3zGX2NixFjcqSUlNFp65cq2Bj23XZbhg9PXuFqnQhuek37Vqdaeb6GY+yoDmKVVRw
         oyVgsjy/47R5iE9JNOL1eOtEjNxuobG8Sub1TJH2jucfRU4w497J7vrW3M9aOtaB+ACu
         8pqxLG0S7eVT+Fcfq3NL1C9XHMD5ngIFqv83OemTRRceDkSM1NqHF2PCYRKjhali9c9C
         XDonNTAIYl4/UQhlxsGBXmIp7BNUIgBFg1zZKuQHYUdfIUEIiqmx8S8luYCtCARCUzEB
         7F4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R7ZP3MarK+ugl8P5WX19zOVhfdMRWuPhBdXyuFEnRFk=;
        b=BVMTEyIEK58GF/dkH9J4b3e8oLuex+ApNKd5vdZ2N4msbx8XVtAGJO0HHr3jvvjfst
         MaDwSRa5DRTTficpxF14JRCo2UP0jCZ/Duw6dipy3zm4vreNVn9uQThmMc99PX2PQEFI
         SYfEQWmDX08WiUrDaE9WNvll2CxuS0YlQ2toNjaBhBG9ZkJbUFvIWp6SRoWhl1Vg5kGW
         YesYiFJWntpCsxODxX2V4/H1WHRlumAMv+FZfGEAvPCzQYoTIq2qnc3q3stzrBIkGlfT
         BhAqQngkJ4GPf5k/CVLwSP4CeD59Ddf9TPyAbCS+y5Qm5lHtAd6oY5ufuirQ2Y4AbDD9
         HHBg==
X-Gm-Message-State: AJIora+9a2hQkY2di7tsQkqDXPLT5/mAl+gdn5lXPmiXKOoF8o9JLz6l
	NKn9uJTCcxVITQDxX9GWh0s=
X-Google-Smtp-Source: AGRyM1ux3zEMyuf4wDhV9F8TtMVJOCzeVWv7eT0b/KvaKtvEOp02v00t8Svq1SHoVQEz27IAKLFTgg==
X-Received: by 2002:a05:6808:b29:b0:335:37b6:3ce7 with SMTP id t9-20020a0568080b2900b0033537b63ce7mr12887039oij.104.1656418255813;
        Tue, 28 Jun 2022 05:10:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1394:b0:335:762d:b884 with SMTP id
 c20-20020a056808139400b00335762db884ls2061648oiw.8.gmail; Tue, 28 Jun 2022
 05:10:55 -0700 (PDT)
X-Received: by 2002:a05:6808:1308:b0:335:5573:b45c with SMTP id y8-20020a056808130800b003355573b45cmr9878266oiv.26.1656418255380;
        Tue, 28 Jun 2022 05:10:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656418255; cv=none;
        d=google.com; s=arc-20160816;
        b=mep70Eoc7u2eQ9ra/p5c9oOTMDpXJs1EWBh+FYVW4QmzSGC2qKjRJmIhT8iD7Wv+Zc
         fmNy9KkYdEPQmHZHJGOc6eMgIWjQf4iJQHEVWLlPJ2V7sUvKH7GWl8qB9Mg5V2InS8LO
         cIjQN+G1ajhysESTIkh5z31MepcSIvMoxabvFyOhuUKlVAkfNl/xkYIUD1TMcTtsUmk1
         wLJsTx+fkZoAIP2CCDfERgMY/Qf7eoVQ7KjuROPqI1UssKyxnnj20W8mSeqHDVKVg8Mg
         ue3jsKz4dsZK6YKWK5xrb7rrX67fvryrpupf2OEvwL4sgosia6KHHgrvuZ1Lr6RuGzTx
         fI8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kivkjIcW/dBwtKQGxzqBhqyQNzFDh/iWcq1jAKuPzjQ=;
        b=fD6XuIVyy32pzTcqkRBrGuJirsEZI+iffCwCNhIl7jvSY3txE8SgCzwQ+x1NmzTzFg
         8n06ElNQ6ezQPBbRFPbtX3xQH4c2q3EYkgfEa1keLI0LV6CcWcKPFN0LsJw+oQ/aJDks
         TaJZXZE69Okk46H/jbpj2s0p+iiAH7QPYFUI7sVIjrGx1S9djVltr5OaCaNMP2dxMdSq
         A/YhRoThxVq+0a9sLwH4WEbTcLKVJ9xfvYOnspPmIDB0iShNeXvF8DM6NCgdUSTYjf7r
         xVNK1pslY+rw/j9SA9ejH5mUTCJR+y3X5j6wP/XdgnIXwLrPMWBqmH/yLeI8Guug8hei
         nF3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CLRflZYy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id u6-20020a056870304600b00101fb24d062si1766244oau.3.2022.06.28.05.10.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 05:10:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id d5so21864167yba.5
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 05:10:55 -0700 (PDT)
X-Received: by 2002:a25:cc56:0:b0:66c:d0f6:2f0e with SMTP id
 l83-20020a25cc56000000b0066cd0f62f0emr10988742ybf.168.1656418254817; Tue, 28
 Jun 2022 05:10:54 -0700 (PDT)
MIME-Version: 1.0
References: <20220628113714.7792-1-yee.lee@mediatek.com> <20220628113714.7792-2-yee.lee@mediatek.com>
In-Reply-To: <20220628113714.7792-2-yee.lee@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 14:10:18 +0200
Message-ID: <CANpmjNNSHEksMq+xR62mV5dzb0ZO7UPhUzt2ghSbqcR-Bsm_2w@mail.gmail.com>
Subject: Re: [PATCH v2 1/1] mm: kfence: apply kmemleak_ignore_phys on early
 allocated pool
To: yee.lee@mediatek.com
Cc: linux-kernel@vger.kernel.org, catalin.marinas@arm.com, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	"open list:KFENCE" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=CLRflZYy;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 28 Jun 2022 at 13:37, yee.lee via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> From: Yee Lee <yee.lee@mediatek.com>
>
> This patch solves two issues.
>
> (1) The pool allocated by memblock needs to unregister from
> kmemleak scanning. Apply kmemleak_ignore_phys to replace the
> original kmemleak_free as its address now is stored in the phys tree.
>
> (2) The pool late allocated by page-alloc doesn't need to unregister.
> Move out the freeing operation from its call path.
>
> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Yee Lee <yee.lee@mediatek.com>

Reviewed-by: Marco Elver <elver@google.com>

Does this want a Fixes tag?

> ---
>  mm/kfence/core.c | 18 +++++++++---------
>  1 file changed, 9 insertions(+), 9 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 4e7cd4c8e687..32a4a75e820c 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -600,14 +600,6 @@ static unsigned long kfence_init_pool(void)
>                 addr += 2 * PAGE_SIZE;
>         }
>
> -       /*
> -        * The pool is live and will never be deallocated from this point on.
> -        * Remove the pool object from the kmemleak object tree, as it would
> -        * otherwise overlap with allocations returned by kfence_alloc(), which
> -        * are registered with kmemleak through the slab post-alloc hook.
> -        */
> -       kmemleak_free(__kfence_pool);
> -
>         return 0;
>  }
>
> @@ -620,8 +612,16 @@ static bool __init kfence_init_pool_early(void)
>
>         addr = kfence_init_pool();
>
> -       if (!addr)
> +       if (!addr) {
> +               /*
> +                * The pool is live and will never be deallocated from this point on.
> +                * Ignore the pool object from the kmemleak phys object tree, as it would
> +                * otherwise overlap with allocations returned by kfence_alloc(), which
> +                * are registered with kmemleak through the slab post-alloc hook.
> +                */
> +               kmemleak_ignore_phys(__pa(__kfence_pool));
>                 return true;
> +       }
>
>         /*
>          * Only release unprotected pages, and do not try to go back and change
> --
> 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNSHEksMq%2BxR62mV5dzb0ZO7UPhUzt2ghSbqcR-Bsm_2w%40mail.gmail.com.
