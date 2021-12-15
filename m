Return-Path: <kasan-dev+bncBCKJJ7XLVUBBB3WK4WGQMGQEU2S23MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id B1CC247517C
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Dec 2021 04:47:59 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id kd7-20020a056214400700b003b54713452csf29184257qvb.13
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 19:47:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639540078; cv=pass;
        d=google.com; s=arc-20160816;
        b=eR7KwynNbHcy0/90L0hJWRB1SPQTPyxPLNhgfU2ufJwLbGKCJBQkjAbn0mr7tnU4Pt
         Rx5bMaQHYTCn4QO2r79gofeCJMFnuddu0Yl+rusngWNBclGdNHGxIvfe+Rtj3vxG0gva
         Aa/xYFSo+42BvQioUTMkn277xIZlI4nRQO+10vjZxLzRws5+w0SDJokAO3M0Q7r3tgkG
         Tebfp6JEait80e1rB60GZFtSWIbqBzcW1432T34XSBikvTvuptMS9QHqLQCkqvPJwAur
         5YSOao4d0ZV+/Jowq0wHQRA3c6BOy4pL1LwwAODqm42NdIK41JPHASIGIxiUmOuep+Ss
         vjLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=+Ql0tUtZfizfFt7GOHqm8VGrxe3ql72GprzoyF2gCYQ=;
        b=BVL+DiDhYU++LBU1vt3EBXhksLwo3F6EY3yHXi2OwMtarv4V7VStz1UVtMUslwkktV
         KY0+GcaP4LAaXnR1l3l+TL5/TbFLGEkYRZACRLbhgbk6ZM73lEP5+S3p3tJUmJBvaqiz
         bfhLvBDMKHQGtqZEDQYrZvjXzQiOG2UJItaiU7x2uTX1I4WrvJmU7Oeuv6Ta7Wxyms0O
         xxSelMrtwmrFglBLx0WUqyQMZIrEwA8lj1JK6YLiOlKioiCPxQ/j/K2r+LJnrRILDXa5
         Wlam770vMywhCVR2H3iHNTL80ThWCx+dc+arLnU232zm07RffY72WRzbJApcSYxxgsNW
         gAKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=WPMmh69m;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+Ql0tUtZfizfFt7GOHqm8VGrxe3ql72GprzoyF2gCYQ=;
        b=iDtgrwYlbY2/JqdQJ7OqJtyB+ba6QjlFyqPhuWQbQpn1qShJhcpNTl36N8N1um00H8
         Qyf8nDN7pge7xWi3c+NPGnub7t8EYCi3vGsmZZ+p0Ol/6l43AsRO4a1D9oNMvWB6Ko1i
         cePFOAf8v5bVC/CShivhA429KAex85HTOz9srnJXIv1HB6n/+WNoYRIeAC5wHqF+vU/Q
         z+sWLo9ywUmYamdJwJ/LNfjgt7/vCawAU02mFeY4fQuXphGiazb3lQjhWHMC+ayH4VAW
         A146ERFwG4hpNAh3Q8G3pU/Rn0XcyAzwQka6tDCKDUD+04FvgofRLrZjFr7NSAI9qA0V
         Y+Tw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+Ql0tUtZfizfFt7GOHqm8VGrxe3ql72GprzoyF2gCYQ=;
        b=jQBp4J02KBGIFGSUyhS2C6ivP98IQ2hI1WEOZqWdLOf8Ppx9Lhn5o6NNIqpNKFMjQc
         zd/tmCeB6lksGf9jLQAM0d7vc8pLxchCzpKdtX5Hyu7gsTCR6HdbRJ6omaUCrZNSZGHT
         qDZo1RmnDs+UCDBgz0R49WhAnpt/dmRfv6ciMzx+v/dv3Sm3+z3GRXGV8KbJK0U9CmPo
         L8tL2xBsvQcInhkESOnj4vcLR0SqD8GQOsr07C8fysuH9vTe11Ya8DniJj57TiBDR14B
         lj/JWAHdd0ftTJ2e2x+gpLwi9jD7BhcRIZ1XWKZhx5A4ywxTFPEJyBd7ne0m5PqFgo/k
         tOkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+Ql0tUtZfizfFt7GOHqm8VGrxe3ql72GprzoyF2gCYQ=;
        b=tKDG+JfX9akj+A+1l7X9r/zC/SrWnVFAfeunEuGInOMm+13McyyZg0RIPYLi3k4dBp
         0iMp2h2w8O/L2Hgg1BYFsDhr2D4BNyBzwc9bk5vKDrQmFEiYV7BCO6B3aXSV5Z72kvlq
         16uTPnahO8FRE1sqa2dofIJQGu1btB/K4TuwiZofbdluj6LT7fjcaIrVfnQz5hKZxrOD
         ygvL0cyBp2q8mysCX7nb6kHIZhOuzxbsGjVJkL7BtSHVgC2itD3JkaEi95MO/L7TQgXp
         Hm7z1WKWbLgFkE+6bT7w9mDBGXRsJ6fA3xuBJ/pRGKCO7niblQZXfUDXLHLP8QjBtzg1
         uXNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532KPI8RtwywpN6XyQ70LpHnkG5b8lmhmoIU6OQ9IWzp1NeWrydD
	W1A3uw52rL82eVqZEipbGEU=
X-Google-Smtp-Source: ABdhPJxmLJ5s9oZZBuvA9uKw7Wwocqy69j3CH1eFZ6TxMASqobiCSdgXu2g+d4erOdbuuFU+1rwq1Q==
X-Received: by 2002:a37:8883:: with SMTP id k125mr7306082qkd.464.1639540078323;
        Tue, 14 Dec 2021 19:47:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:4048:: with SMTP id i8ls467662qko.2.gmail; Tue, 14
 Dec 2021 19:47:57 -0800 (PST)
X-Received: by 2002:a05:620a:44c1:: with SMTP id y1mr7409385qkp.647.1639540077880;
        Tue, 14 Dec 2021 19:47:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639540077; cv=none;
        d=google.com; s=arc-20160816;
        b=SO1+bD9d2PPpJ8wuqiXmE7nvTt5+RAYE4mMKV518dnGHfIoLuBmGgAqrwVG2DxpLom
         SnJMfii9Doc+b3RQsoXRJqCZWhERamRW4YXJsMBSpW89g8+uEUiudey3CQq3LIYMk+Ao
         +DgEKtGhcwOwDwOZLDBNOW4FsJKJKVc5LG1jYRnhw1D5kL/SRD4zs1iY4Tzn8Ehowgv8
         q9y0UAYD5+UCiio4jr4xbH4oUPV+WQiZRHS0lzMFcclbvRWp97iN2Sh0T9X1ieAjJQ5X
         RYJcF4kSSK51YBsw0w61Xx2R4kNvX4sosqhHm64AKwDPbljdUHzWq+l0qrtS+8sMcFiW
         NQzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WX18AvwNcCC2p0SRhjMK6GhbrhT1JBIKs0M6zY3Lj7Q=;
        b=D+inQJqmlbENIdwJ/Mlx0tBOq39xGXfhtHE4M2Qg2Pjask3AYGq8ktFGLyiceNzIbX
         K9/kMu2POvBd4A0ur3zeNUA8jQN4wtoEX6dN2mV1PRzwb5JW3DIqKBLsJ+XFocywea9T
         vLKCiqyutmLthj3cRfkJnfbCByjaUzTQ+2u76NE/w8VuxjvBf3mwkhsCEmT1gs8KAmi6
         n5HUGqu0epxd+wfl6Bd2JUz9765qoC1UhkM3dOyRyRcFDfPPSATAq1rlTU8leBz1HcFe
         jL02pWpPnHz6FrtwjXryXJcGRO4xBazXc+EfbpgV4mQK58BITsySck10yg6EUd76b14+
         E91w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=WPMmh69m;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id i18si73607qtx.0.2021.12.14.19.47.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Dec 2021 19:47:57 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id f74so2175792pfa.3
        for <kasan-dev@googlegroups.com>; Tue, 14 Dec 2021 19:47:57 -0800 (PST)
X-Received: by 2002:a62:7a54:0:b0:494:6e78:994b with SMTP id v81-20020a627a54000000b004946e78994bmr7244240pfc.5.1639540077124;
        Tue, 14 Dec 2021 19:47:57 -0800 (PST)
Received: from odroid ([114.29.23.242])
        by smtp.gmail.com with ESMTPSA id x11sm418405pjq.52.2021.12.14.19.47.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Dec 2021 19:47:56 -0800 (PST)
Date: Wed, 15 Dec 2021 03:47:46 +0000
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	cgroups@vger.kernel.org, Dave Hansen <dave.hansen@linux.intel.com>,
	David Woodhouse <dwmw2@infradead.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	iommu@lists.linux-foundation.org, Joerg Roedel <joro@8bytes.org>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Julia Lawall <julia.lawall@inria.fr>, kasan-dev@googlegroups.com,
	Lu Baolu <baolu.lu@linux.intel.com>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Marco Elver <elver@google.com>, Michal Hocko <mhocko@kernel.org>,
	Minchan Kim <minchan@kernel.org>, Nitin Gupta <ngupta@vflare.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vladimir Davydov <vdavydov.dev@gmail.com>,
	Will Deacon <will@kernel.org>, x86@kernel.org
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
Message-ID: <20211215034746.GA1097530@odroid>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
 <20211214143822.GA1063445@odroid>
 <87584294-b1bc-aabe-d86a-1a8b93a7f4d4@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87584294-b1bc-aabe-d86a-1a8b93a7f4d4@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=WPMmh69m;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::433
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Dec 14, 2021 at 03:43:35PM +0100, Vlastimil Babka wrote:
> On 12/14/21 15:38, Hyeonggon Yoo wrote:
> > On Tue, Dec 14, 2021 at 01:57:22PM +0100, Vlastimil Babka wrote:
> >> On 12/1/21 19:14, Vlastimil Babka wrote:
> >> > Folks from non-slab subsystems are Cc'd only to patches affecting them, and
> >> > this cover letter.
> >> > 
> >> > Series also available in git, based on 5.16-rc3:
> >> > https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v2r2
> >> 
> >> Pushed a new branch slab-struct-slab-v3r3 with accumulated fixes and small tweaks
> >> and a new patch from Hyeonggon Yoo on top. To avoid too much spam, here's a range diff:
> >> 
> > 
> > Hello Vlastimil, Thank you for nice work.
> > I'm going to review and test new version soon in free time.
> 
> Thanks!
> 

You're welcome!

> > Btw, I gave you some review and test tags and seems to be missing in new
> > series. Did I do review/test process wrongly? It's first time to review
> > patches so please let me know if I did it wrongly.
> 
> You did right, sorry! I didn't include them as those were for patches that I
> was additionally changing after your review/test and the decision what is
> substantial change enough to need a new test/review is often fuzzy. 

Ah, Okay. review/test becomes invalid after some changing.
that's okay. I was just unfamiliar with the process. Thank you!

> So if you can recheck the new versions it would be great and then I will pick that
> up, thanks!

Okay. I'll new versions.

> 
> > --
> > Thank you.
> > Hyeonggon.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211215034746.GA1097530%40odroid.
