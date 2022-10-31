Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBSXG72NAMGQEH7OIEGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 138ED613492
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Oct 2022 12:36:44 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id c13-20020a4a380d000000b00494059ad6f0sf3849986ooa.9
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Oct 2022 04:36:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667216202; cv=pass;
        d=google.com; s=arc-20160816;
        b=fRCCeogBz9AwACugZH+6LH0Pr70vhqknFAFagpDUzVzGOU6q0DMZy5iAEeI4M5gJnI
         jMxMVTeDbCUJzzzygBBUiZ1E+Si/vX+KpZWdalt8WjrvccXkldys5Ycndyq+9YOd4rcz
         JA+ntxQazye1qNQgPPAGMDMjrSHJnoBeXrwT2o9PnJIfq+izcqA2q4e+JCUsBsGAsCo9
         fG2X5pNHEWYI/v/3cQ7aHqaStebIx2GO+RJd1vCld8on5/zDZzGtO8zxRXr3yOdkjMbj
         xrg7U23pLOmfjqZIMb1+528x70wZRw55jWJcVl7J+K5gfnPvzZpKUkKekLX6jLJTsI5S
         RY2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=BVjnYWyISwRUx3Uq41lCaxgKE8ucnQqq9+ZJYfYzDqA=;
        b=vI5N8pxWFJlvC1Hz+3nW7DZFWNlP7gUNIgF/19LZXWPlMWKOgEZPkWS4BMTlX3GUjn
         Bp21baK4OtLa6RpYq2Dl5sjwuYoPFH6G8ryhDs+eY1OmRvLwHpxmbovCoATqEhSWv/RE
         JQy8L7uKvY4sZ2o472aKHkQ46/F1wcuVOx8Oul/b3gMphCDCsd+wW9goCWANNpvlqp+g
         yq62SBEfP3DCgIi2enUPmlE8GKTB47VGhsCo3cFRFcOodFG9dshaJb9/AIUf2AMYVJfn
         J9YyhRPMLtlXH4mZlzjzoK9PW4qE+f30vgfgZvhe9AKVd8xQzwcFvwejK69bEj8q+J70
         6OhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=G53K5YU2;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BVjnYWyISwRUx3Uq41lCaxgKE8ucnQqq9+ZJYfYzDqA=;
        b=a4xJtGM3+jNSD3m3bRJp028fhUVMV/GNg4L74Ww1uyr9XzctkJ17ON3YvFYpMCGjYw
         SmQRlPuYDXi4aJfSiUrBDohnpdVEoj4PRXNxU78ocsYJlPMbWytnM1NS0RUootpncbLo
         wk7kreaH1l+LZrYruS/IxdElqAmCN40AYDCVPPzEzkgNRNuwk8VzR1ylcRO1ZTGrOhvY
         Wv1LwtgDfuz7b23Qp+e5z8jl3UXCF6qXoormidzA8+vpmLbxLw1rMDoM8BLbchFMaxlq
         HX0b5GGRlmU4gc9pG1iWRsIkhwJxAs5lNp9MOl8czfGQOQKIlXtKL4cXWdhPljczgKL1
         YCTA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=BVjnYWyISwRUx3Uq41lCaxgKE8ucnQqq9+ZJYfYzDqA=;
        b=RwKfuChTR0LImrYqrRNKXv57sqrgCYmWYIcVAxOGl8In6cYWz0Bm1IXdoxXDmJwChd
         kfcZAe+icsHNmiehiryX0GDZj0sQ1YlYs22ZWZe+R6SgZ5wU0+mgg5282DH6SnZm7UN+
         GUXb9YTOF7MfkQS1W65s1zgRIfImPLRvUdKFOtyWmkk0XEW+WQ+Bbo7wEIJ67jTMz8l/
         TniV9kTJMkb2qdlObCNkSBqasUs4G/2ha3zLio6k7hwDhoqcZsZf7iPtz68mikD7uAEd
         2hZJ0F0lt4V+KuNLsg6oV60XUrOKlgnhvZGPf5ziJbpFzlFXDeYjM165F824fzoct29K
         Tkkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BVjnYWyISwRUx3Uq41lCaxgKE8ucnQqq9+ZJYfYzDqA=;
        b=FcQUA/so45KGMxGw4jHghLBGcNdrFJpBOGTvUF8Fa+rm3S+M/nrdw3A+LbL3aq/M/J
         u27ou+TJ5AJNmm0AvSs3W7RRyExtdlEcqDr7csEemtj46TK9mOz9y89vM/+moOWiH9xT
         eD9lu0iarBQmwUCEDnVWcLspZbWqRLzCXbTe0aX9QekIhM/pXZxhk+vX2YDK8MGi8YTi
         i1IQS30Ca5+M7+cmGV5k3aF1dhpGqFeV46j1LRfXm/UchuqjeUBE7N2D/TL9ngGd0siT
         hAn6TVKU4iM0cBrtIx/sM0UO8LJuRWznEQT6oNNmJUfPlJwqen7hL1k4E04BBTCcfhKK
         QAmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2KsarFg35t5LYjE3qbHjrK39siNXduFDJv4rJQWVaTHt7pMywm
	vfTl9Fwl25dmnstOpiyyifw=
X-Google-Smtp-Source: AMsMyM49HEbrSgIVtm6Z1tDc4VUqKvveSArOZvg3RXXdPm4MiCuKl8UuRGksyl8/VsAL5ehcOJuvnA==
X-Received: by 2002:a05:6830:4115:b0:661:a2c4:3bcd with SMTP id w21-20020a056830411500b00661a2c43bcdmr6473110ott.368.1667216202684;
        Mon, 31 Oct 2022 04:36:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4e99:0:b0:66c:532c:d353 with SMTP id v25-20020a9d4e99000000b0066c532cd353ls369649otk.6.-pod-prod-gmail;
 Mon, 31 Oct 2022 04:36:42 -0700 (PDT)
X-Received: by 2002:a05:6830:438b:b0:661:ac06:d4fe with SMTP id s11-20020a056830438b00b00661ac06d4femr6334570otv.231.1667216202070;
        Mon, 31 Oct 2022 04:36:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667216202; cv=none;
        d=google.com; s=arc-20160816;
        b=m/ukE+SwcCG9HIRsGyGxoEZLSrLpVFdtwlTIc0z+Eyy+YG1QA6ZQAjjqI5/OLz+ftZ
         H5lrf7ahpOJ9B8KAVbwTqlZcBdZVAKCPNwyH7rMZdTS7iPPOYQJHTQy+47HU5QtvzWSy
         WXuFIOeSOgJNqB9E6Mt0ncEttw+pwyy7Sc7XacKVg9J6xiI9jznxNNaN4xkKXGVxHcD8
         Xp0fak4ZPbHjkBDTp2nfk+hKbstZrZEWFTbRxCBdkL4u+mPAwGfRlx4uNMLvnXfHH0el
         9UlRAbGXY69oM7dWkEjaLcA5QxdVgJcCo43vJvJeHGTOdCFFyD/CgzMLEzGWsEqw7mTJ
         5b5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=tk8T8KciNnKClZtt9a7oM7hEZLA8ALbiZujS1/Z8e40=;
        b=Wr7CiPYigFUQctGm7xPf86BsRqPJZvviBojBXeGzalRCAII5xS4UE7bZqhTK7werQ4
         BXOeGd8e1mmvLTkeA3u0mBFIsGPqV9CElUSLHLY/rJrzCQBmKMgMqYeEF1ZM1J5NSPkV
         vOjxBsg+YCtcCjemtxUZulh3eFa5p85+di63AxNHP4ZgsNJgfIHg66iU8qX+rNl2Lfa6
         H+Vhl+eJQYkXEoLCHaBj0Z56dNgRedBI5ofd7qVB+gvIx4GY5tLUaKc+CuD0GDpplvAE
         pGvMHTPdsS+voCmQXW8PP/wlvyVwpU/KOS1Ywi4Ljd65b/1gLcyPriZTtFODKFLCedx9
         zDHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=G53K5YU2;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id 64-20020a9d0346000000b0066c34c88dc2si317477otv.4.2022.10.31.04.36.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 Oct 2022 04:36:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id 128so10471210pga.1
        for <kasan-dev@googlegroups.com>; Mon, 31 Oct 2022 04:36:42 -0700 (PDT)
X-Received: by 2002:a05:6a00:14cc:b0:56b:9969:823 with SMTP id w12-20020a056a0014cc00b0056b99690823mr13659260pfu.36.1667216201343;
        Mon, 31 Oct 2022 04:36:41 -0700 (PDT)
Received: from hyeyoo ([114.29.91.56])
        by smtp.gmail.com with ESMTPSA id v17-20020aa799d1000000b0056bb191f176sm4526205pfi.14.2022.10.31.04.36.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 31 Oct 2022 04:36:40 -0700 (PDT)
Date: Mon, 31 Oct 2022 20:36:33 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: John Thomson <lists@johnthomson.fastmail.com.au>
Cc: Feng Tang <feng.tang@intel.com>, Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	"Hansen, Dave" <dave.hansen@intel.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Robin Murphy <robin.murphy@arm.com>,
	John Garry <john.garry@huawei.com>,
	Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
Message-ID: <Y1+zQShofiGTxcKG@hyeyoo>
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-2-feng.tang@intel.com>
 <becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com>
 <af2ba83d-c3f4-c6fb-794e-c2c7c0892c44@suse.cz>
 <Y180l6zUnNjdCoaE@feng-clx>
 <c4285caf-277c-45fd-8fc7-8a1d61685ce8@app.fastmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c4285caf-277c-45fd-8fc7-8a1d61685ce8@app.fastmail.com>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=G53K5YU2;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::534
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

On Mon, Oct 31, 2022 at 10:05:58AM +0000, John Thomson wrote:
> On Mon, 31 Oct 2022, at 02:36, Feng Tang wrote:
> > Hi John,
> >
> > Thanks for the bisecting and reporting!
> >
> > On Mon, Oct 31, 2022 at 05:30:24AM +0800, Vlastimil Babka wrote:
> >> On 10/30/22 20:23, John Thomson wrote:
> >> > On Tue, 13 Sep 2022, at 06:54, Feng Tang wrote:
> >> >> kmalloc's API family is critical for mm, with one nature that it will
> >> >> round up the request size to a fixed one (mostly power of 2). Say
> >> >> when user requests memory for '2^n + 1' bytes, actually 2^(n+1) bytes
> >> >> could be allocated, so in worst case, there is around 50% memory
> >> >> space waste.
> >> > 
> >> > 
> >> > I have a ralink mt7621 router running Openwrt, using the mips ZBOOT kernel, and appear to have bisected
> >> > a very-nearly-clean kernel v6.1rc-2 boot issue to this commit.
> >> > I have 3 commits atop 6.1-rc2: fix a ZBOOT compile error, use the Openwrt LZMA options,
> >> > and enable DEBUG_ZBOOT for my platform. I am compiling my kernel within the Openwrt build system.
> >> > No guarantees this is not due to something I am doing wrong, but any insight would be greatly appreciated.
> >> > 
> >> > 
> >> > On UART, No indication of the (once extracted) kernel booting:
> >> > 
> >> > transfer started ......................................... transfer ok, time=2.01s
> >> > setting up elf image... OK
> >> > jumping to kernel code
> >> > zimage at:     80BA4100 810D4720
> >> > Uncompressing Linux at load address 80001000
> >> > Copy device tree to address  80B96EE0
> >> > Now, booting the kernel...
> >> 
> >> It's weird that the commit would cause no output so early, SLUB code is 
> >> run only later.
> > 
> > I noticed your cmdline has console setting, could you enable the
> > earlyprintk in cmdline like "earlyprintk=ttyS0,115200" etc to see
> > if there is more message printed out.
> 
> Still nothing from vmlinux with earlykprint on UART unless revert.
> 
> >
> > Also I want to confirm this is a boot failure and not only a boot
> > message missing.
> 
> Yes, boot failure.
> Network comes up automatically on successful boot. Not happening when no kernel UART

It is really weird that I see no boot issue on my MIPS emulation with almost same
config, with different target - Malta board that QEMU supports. it just boot fine.

Can you attach debugger to the board?
(Which I hadn't tried. I had tried it only to QEMU)

[...]

> >> > 
> >> > 
> >> > possibly relevant config options:
> >> > grep -E '(SLUB|SLAB)' .config
> >> > # SLAB allocator options
> >> > # CONFIG_SLAB is not set
> >> > CONFIG_SLUB=y
> >> > CONFIG_SLAB_MERGE_DEFAULT=y
> >> > # CONFIG_SLAB_FREELIST_RANDOM is not set
> >> > # CONFIG_SLAB_FREELIST_HARDENED is not set
> >> > # CONFIG_SLUB_STATS is not set
> >> > CONFIG_SLUB_CPU_PARTIAL=y
> >> > # end of SLAB allocator options
> >> > # CONFIG_SLUB_DEBUG is not set
> >> 
> >> Also not having CONFIG_SLUB_DEBUG enabled means most of the code the 
> >> patch/commit touches is not even active.
> >> Could this be some miscompile or code layout change exposing some 
> >> different bug, hmm.
> 
> Yes, it could be.

What happens with clang?

> 
> >> Is it any different if you do enable CONFIG_SLUB_DEBUG ?
> 
> No change
> 
> >> Or change to CONFIG_SLAB? (that would be really weird if not)
> 
> This boots fine
> 
> > I haven't found any clue from the code either, and I compiled
> > kernel with the config above and tested booting on an Alder-lake
> > desktop and a QEMU, which boot fine.
> >
> > Could you provide the full kernel config and demsg (in compressed
> > format if you think it's too big), so we can check more?
> 
> Attached
> 
> > Thanks,
> > Feng
> 
> vmlinux is bigger, and entry point is larger (0x8074081c vs 0x807407dc revert vs 0x8073fcbc),
> so that may be it? Or not?
> revert + SLUB_DEBUG + SLUB_DEBUG_ON is bigger still, but does successfully boot.
> vmlinux entry point is 0x8074705c
> 
> 
> transfer started ......................................... transfer ok, time=2.01s
> setting up elf image... OK
> jumping to kernel code
> zimage at:     80BA4100 810D6FA0
> Uncompressing Linux at load address 80001000
> Copy device tree to address  80B9EEE0
> Now, booting the kernel...
> [    0.000000] Linux version 6.1.0-rc2 (john@john) (mipsel-openwrt-linux-musl-gc
> c (OpenWrt GCC 11.3.0 r19724+16-1521d5f453) 11.3.0, GNU ld (GNU Binutils) 2.37) 
> #0 SMP Fri Oct 28 03:48:10 2022
> 
> 
>  I will keep looking.
> 
> Thank you,
> -- 
>   John Thomson



-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y1%2BzQShofiGTxcKG%40hyeyoo.
