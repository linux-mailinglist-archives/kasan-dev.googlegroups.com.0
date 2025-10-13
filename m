Return-Path: <kasan-dev+bncBCUY5FXDWACRBM7AWXDQMGQERWLYFII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 73F5BBD65F6
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Oct 2025 23:33:40 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-46b303f6c9csf42916675e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Oct 2025 14:33:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760391220; cv=pass;
        d=google.com; s=arc-20240605;
        b=Uo00et03o0wUy9dZ2Hip6M1XMD21HBePmZmi6ABoDnMamBgy6VMN/oBQJvm62n5suq
         VB752wvQUDoe7I7N6X5tl5g+efRbjInWnzrxI2afGivvKek7mflAc0K98AVlB2YX/WaX
         rvB6kFaGGxSFN8zhOo5KoXBxlmUaEjxZQYBbV1sFRztcvipxSF42+HNzfLJN/Zg87355
         J28fikGpFcLhzz3wqws3cFp4TmDsWx8h6isAMxzYp/1fvkYh4sUNrhWL9NIPRyST1aIN
         77xPfIefVTeBq8EeackxEjS25sNAyfvw3lQ3cGhe4cmDy4AgHQRxEm/Iia2o7QDqlspK
         W5CA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Z6odH9BRGrjyGEwSQJAKFQX03y7d1ZV5FCeDbEuyez0=;
        fh=minRE8eShcJRcB4PdxyqSSB5FX36qx/Lb2RPgZ2u/S0=;
        b=ESF35gutKXjeZarmpK8HGefqMWxRG0IMYvZ+X2OBKvF0W37eZ2eKr32aB8PJaVPjNU
         hfKEazSLkPGMhgalkffefJDsS+AW2XvCfBYOL6PVdXRct8An+xxJw2Iycjqo2h3eFJLS
         NPVd8jWKWr46rnI3KNQCJRgCskmuVhyemtjnarRG2kxCi2+HLrS3BEpsHP8P+Dwu2bVb
         nMnPB41qdxrSvOV0LGzADwBEUSjX9vtP0wQdxFrBIkuMEKelep20GPaTg16bY6GYedf4
         1DE0ktawzH2T4RXU5jMTyqQ6XRAwJQWd/izb7441/QvOciOyrflKG+CSHVybYVlQrR6y
         7/eA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=X50lICU3;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760391220; x=1760996020; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Z6odH9BRGrjyGEwSQJAKFQX03y7d1ZV5FCeDbEuyez0=;
        b=qV92Ry+qTML6LZTiGkWG5suvaMfUx9AHSXDB+dUofjFpWa7NrSCDu8GcRN8Lkeppk7
         AXLfBgaEjAZSlwNDujT9FzsWvnEBYY2D+y5sAibFa3rc3avoxhOM0tv5OUi5rCOqinqV
         tf2v4ZbLzo7qpp3TfE5Pbm5G+CRIKKgvqjHzB2QdrjLi9Rsu33A7dyr5cvk1RtWSxAvO
         GVwoYdWvpGiTQkhV2MNqRL3THgKGuzhh3KK8pcbytsKQAc2XyinOy0of17Yhc7dTPydp
         UNRlA3YL3DK5k60ZpCaiXwgHgvthGlvmFJ94b9PTSCN/ZIVlfKzDVinRKQucPRYSLxvr
         n4RQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760391220; x=1760996020; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Z6odH9BRGrjyGEwSQJAKFQX03y7d1ZV5FCeDbEuyez0=;
        b=jAM7Zan/1kSV//WufRE5T60kWMqyHMnWHLlBQ3U/8ysWAjzx5KMI4ZrHlqWy8Sfpqz
         tFOhzWF2rGqmmgCV25wSS8o4CgbU+wmxZR+rITVY8rbuGjt0k/8YqlMlgAtWQMmDtmna
         17n9MZXz/W/RxBTtw3wKxAOdW2pEG2udTbXHeb0xXin6uLjbmrqGkCAzZH9+i8V/Xz3s
         kcDp1lvsdxLD80cWYSY0efwb4zjWKtA7kshT7HUsEgBISMlgAi+yVp4Ox5Y4j3ihuQqu
         a5SteA5cP3lgv5K3uNpzIbSolSCLJ22eM9bKvdxkSJ1Fl3se50IZFmuW6GdlJ/YJHESL
         1nQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760391220; x=1760996020;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Z6odH9BRGrjyGEwSQJAKFQX03y7d1ZV5FCeDbEuyez0=;
        b=u+mIWuK4qVuHwDK9pl6iCowVDEGq2acxOcGhzvS+GcXDbu4aNAQhN7SwQGbgidHEiw
         KQEUkgPNb6nrMneILrI3aUNfCrKuFzVhSM2BhaIMnk0JIuiPQVUr/Yq1Iryx+Bk1yfph
         6cUUkLGs4qwRlPp4BtN2zl5+qd4eM8jIz5NgtHO8Rg6qavBRpdbwloFxzPZRN/KmrQ1f
         qEcXGWGwsVTcBKFr1sAxnkHZz0axdpgLJ8+X+P7F8AR7zGFkIKHyl+io+vlF5o15Q5jk
         F2QN6BnEQH0uv8RY6IVk6UM3b0RvFT35LchloEXGpjZapzPMmgp9D6CbnyKgo1nTULOy
         TWhA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXLc+de3C0V6NcH4gs4hx80rTKouFSqHulGc4tqwWzo0T7UPbWcQFAhFLOkttPLO403hQkBRA==@lfdr.de
X-Gm-Message-State: AOJu0YwKGQpqNkpnXzqDHHz0MEQIXoirsq9LFLNolM06lSAEDWieD0J0
	AYf15fyl7OiglnIwGX+pVzN64wVPFbaH6cLPP+05Yhz1qtsO2tAjmsBf
X-Google-Smtp-Source: AGHT+IG0prrx0EuOIHJQ0IpEoO8aXrqLgPFm1kk2NwfDIgQZ+YN1axhzYpq8jpqPrlWknNC9+TVX3w==
X-Received: by 2002:a05:600d:a:b0:46f:b32e:4af3 with SMTP id 5b1f17b1804b1-46fb32e4c1bmr91997695e9.1.1760391219713;
        Mon, 13 Oct 2025 14:33:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5fCNiMSCEfFC8X6+2L/kbpX3mXVgbrEDyF4gF7tN+HQA=="
Received: by 2002:a7b:c84a:0:b0:46e:1d97:94c3 with SMTP id 5b1f17b1804b1-46faf62f714ls26334185e9.1.-pod-prod-09-eu;
 Mon, 13 Oct 2025 14:33:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWkIVnP5bobImOE3HWaQNm0ZLv6wevz7ebdmWhCU9lT+H483iNkXJL/92etsrSRWdXVLzeWCeiDJrE=@googlegroups.com
X-Received: by 2002:a05:6000:4027:b0:426:eed2:728e with SMTP id ffacd0b85a97d-426eed272a1mr206862f8f.29.1760391216657;
        Mon, 13 Oct 2025 14:33:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760391216; cv=none;
        d=google.com; s=arc-20240605;
        b=TRcutdAHae9IKBa6XHzUqvhbICCborKsOspRQ2yHABBBOGT010PXgs5prnjFSumkVM
         l9Ooed+LW+XBjw6k98NEth3dEhnV1cAYpwihs7j8FkUEcADsOVR1ByKqPa7PRkaIl1r6
         SGs3Rwa2toGv+xuQW4b4nWgPMDzOc/WNQbwBPm4IxJW1HifXAamsQvQHER1yNt0CKg5J
         Nk+0M5vRIdXBviZonlXof/CI79GXHOo1TQAj9B2lTp3dacW8EiVqtR+vj9bNvQDNQ/y6
         NEZZsMMAisVmumWs7qJbvV3TIZo3Hj/v1m+H/6Z2JVwGP3J1GlTOBmDJweEGyUspDp8n
         kxlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9ZUcfu/lY1a0PBj+NQhiKBcjA+Mj4IzkP02rncu56NU=;
        fh=ZpxWT4Vok3WZI+7LnMPyuALsyOJQWz7zUgbA5Rywy9Y=;
        b=AI/peP8Ah5Va9bR+f2NBiL2RArVYa5QqFWppWs+KZ3HiHwfhHWurQNBEZBMqw1PmI6
         C18Gju7FB9MW/q4Vd4MqNIzzgL4KrXKGtGMHe/T6C/+02oWm2rGv7VICj8Z4d2XF9xuG
         i7LfUpQw7NZ6VVTglyt1NIbukpzAIoNJSNGhOyHt99Z4bUrymwCoMYKH7lG96PZYz/S8
         5Be++CQG3LHvcrs8TToaDC2RBR2DsaJXvg3Ib2pIWyhOETCqsH0abzgAF2UhR5HmfiEP
         4iOCXnViie4GvcCcdAcbR5r5S+UstE1rPwZgZpbqPzwlQVt3RWF4NHdqQCgdKiXrjbof
         Iuaw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=X50lICU3;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-46fbd8b34f8si929975e9.0.2025.10.13.14.33.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Oct 2025 14:33:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-3ece0e4c5faso4427673f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 13 Oct 2025 14:33:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXorX036RkY+V1uqb9zVwv5zsrLvFreIZeb/LokQ6TWXwg4CWQ4YchOrjGg6ag0Lh8UeiQThc8E0Ro=@googlegroups.com
X-Gm-Gg: ASbGncv0LBfqnnRRYbzjkj6lSjMLPdo0snHlZgZ43hj17Fd4bZZ7diHfMYgIkT3mayY
	bF53eKluKsEMhUv+5F5zyvuBqZqU9WCa31BAOX0tB2vxw+u8FWA+1HcCW0G3k3717edWVmcfSAi
	n3Hkc2fWtBwV5wGao/KNegg5KgugbZevOYlqcllx8C9IV1XEKxeP2B//1Oh8dGmTLNrZBOD1MKe
	vYxcZUy+nzYrdturgnaQajCwASsPpPGZl8KVgyClPQzogF+iQODQCHC2wMwj+iE+vCfLQ==
X-Received: by 2002:a05:6000:2c0e:b0:408:d453:e40c with SMTP id
 ffacd0b85a97d-4266726d9famr14296862f8f.25.1760391215858; Mon, 13 Oct 2025
 14:33:35 -0700 (PDT)
MIME-Version: 1.0
References: <202510101652.7921fdc6-lkp@intel.com> <692b6230-db0c-4369-85f0-539aa1c072bb@suse.cz>
In-Reply-To: <692b6230-db0c-4369-85f0-539aa1c072bb@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Mon, 13 Oct 2025 14:33:24 -0700
X-Gm-Features: AS18NWDZt8nn8SNzaUniYFQxsv0RyUfuDnFuvS487pngygUdhSUHcYIgCPrXOLo
Message-ID: <CAADnVQJLD7+7aySxv+NtS9LMFgj-O=RhSjkF3b-X3ngwzU2K4Q@mail.gmail.com>
Subject: Re: [linus:master] [slab] af92793e52: BUG_kmalloc-#(Not_tainted):Freepointer_corrupt
To: Vlastimil Babka <vbabka@suse.cz>
Cc: kernel test robot <oliver.sang@intel.com>, Alexei Starovoitov <ast@kernel.org>, oe-lkp@lists.linux.dev, 
	kbuild test robot <lkp@intel.com>, LKML <linux-kernel@vger.kernel.org>, 
	Harry Yoo <harry.yoo@oracle.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:CONTROL GROUP (CGROUP)" <cgroups@vger.kernel.org>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=X50lICU3;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Mon, Oct 13, 2025 at 7:58=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 10/10/25 10:39, kernel test robot wrote:
> >
> >
> > Hello,
> >
> > kernel test robot noticed "BUG_kmalloc-#(Not_tainted):Freepointer_corru=
pt" on:
> >
> > commit: af92793e52c3a99b828ed4bdd277fd3e11c18d08 ("slab: Introduce kmal=
loc_nolock() and kfree_nolock().")
> > https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git master
> >
> > [test failed on      linus/master ec714e371f22f716a04e6ecb2a24988c92b26=
911]
> > [test failed on linux-next/master 0b2f041c47acb45db82b4e847af6e17eb66cd=
32d]
> > [test failed on        fix commit 83d59d81b20c09c256099d1c15d7da2196958=
1bd]
> >
> > in testcase: trinity
> > version: trinity-i386-abe9de86-1_20230429
> > with following parameters:
> >
> >       runtime: 300s
> >       group: group-01
> >       nr_groups: 5
> >
> >
> >
> > config: i386-randconfig-012-20251004
> > compiler: gcc-14
> > test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m=
 16G
> >
> > (please refer to attached dmesg/kmsg for entire log/backtrace)
> >
> >
> >
> > If you fix the issue in a separate patch/commit (i.e. not just a new ve=
rsion of
> > the same patch/commit), kindly add following tags
> > | Reported-by: kernel test robot <oliver.sang@intel.com>
> > | Closes: https://lore.kernel.org/oe-lkp/202510101652.7921fdc6-lkp@inte=
l.com
>
> Does this fix it?
> ----8<----
> From 5f467c4e630a7a8e5ba024d31065413bddf22cec Mon Sep 17 00:00:00 2001
> From: Vlastimil Babka <vbabka@suse.cz>
> Date: Mon, 13 Oct 2025 16:56:28 +0200
> Subject: [PATCH] slab: fix clearing freelist in free_deferred_objects()
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 7 ++++---
>  1 file changed, 4 insertions(+), 3 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index f9f7f3942074..080d27fe253f 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -6377,15 +6377,16 @@ static void free_deferred_objects(struct irq_work=
 *work)
>                 slab =3D virt_to_slab(x);
>                 s =3D slab->slab_cache;
>
> +
> +               /* Point 'x' back to the beginning of allocated object */
> +               x -=3D s->offset;
>                 /*
>                  * We used freepointer in 'x' to link 'x' into df->object=
s.
>                  * Clear it to NULL to avoid false positive detection
>                  * of "Freepointer corruption".
>                  */
> -               *(void **)x =3D NULL;
> +               set_freepointer(s, x, NULL);
>
> -               /* Point 'x' back to the beginning of allocated object */
> -               x -=3D s->offset;
>                 __slab_free(s, slab, x, x, 1, _THIS_IP_);

Thanks for the fix!
Acked-by: Alexei Starovoitov <ast@kernel.org>

The bot spotted it with CONFIG_SLAB_FREELIST_HARDENED=3Dy.
It wasn't part of my tests. Sorry.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQJLD7%2B7aySxv%2BNtS9LMFgj-O%3DRhSjkF3b-X3ngwzU2K4Q%40mail.gmail.com.
