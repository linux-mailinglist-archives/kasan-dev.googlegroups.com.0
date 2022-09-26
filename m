Return-Path: <kasan-dev+bncBCF5XGNWYQBRBSMQZCMQMGQE6ARDBAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AA835EB1E7
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 22:15:08 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 69-20020a630148000000b0043bbb38f75bsf4512387pgb.6
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 13:15:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664223305; cv=pass;
        d=google.com; s=arc-20160816;
        b=iBjOyblzlkCFf6Znue3dBOVpP1gKfvlNzH/tle1uOSOWoDJEbu+C/PiceeE0fkOAHe
         E6BMwzuCLnf8rY7WifXHyxCJENTZ7j2f4+qn2zR3qDRar75IwDTyR+qktFmH7JLrtiud
         sK/1y0izthLVzPWmL3K7QJKmzDWe3vhACZyQMEBokU/t+nxFwpr/3x5QZwE+FZNXalgg
         pM8I1LGt70vytQYisi8QUVbKHltBjTp8o03ZBPDs654fxbMjyQ8eVALb9q5mJW9TjEr+
         6kNLvFJP9ijxORIbshRkahy0wDAg8+bnUjJxoNQtsBDx99McK3KQJw39BvOuXCQqhDml
         JMSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=nyOVQ5PVOO374i50u4N6N+QA6erx4dDa+XGKhttrEt0=;
        b=E9FJ/Rj/hxOuIoEesPd9f6h0LQUFzv+Vn3RYXCXZKCmXb7VBRVBU7M+o1uMlbUPCST
         EnkEF8iC/XRg9XTAcFyanvW19XHddgj1kvSlkcjNKTkwqe3MWaOJbyimsE0wAtpbuxkS
         Dfs37dBZwYvaSS0rjR5uk4p3RbJmDt6CJvd1lA4sTFZ0rwRSBK6tE0RZ95XD4Rvj0Gbr
         kZwNMmMW9z7h4jX/+MIW2xel74ovCcq96nyAt4be+u2rKUL8QlT+ztc35n7LIWthSqeT
         jUm8575YECOltc1AcevmOqYeS7AGqcCYt2m+yAt4hO9xsA0MqPc4EYSEYlOiEjsoIxff
         sYZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=U1taE2UK;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=nyOVQ5PVOO374i50u4N6N+QA6erx4dDa+XGKhttrEt0=;
        b=GW4rCpSZ68w8M6GDBplE6KCZgvouuCxKAStteD+t8qflFFI2vLIbpGNKHXbJEoQI1n
         E59GhDIsCE3/2cDHYxN/GKZfTfBy73IiDfbb19j/ptdhKpsXSKFZCF9xt2MBR+/OnGRO
         xCjNIwEqo5hh6Y1axmPa/snlvh5rKpU0ws7F5QjxPGf+s5YYEQSyTYEPivsXZkbzuFj/
         YStcA9Xg2hAuI1iu89ax/X41n2hERdThftpm7qh7Gvh7H1xI9tKej5Wl7sW2GmnMXFTh
         iwK/heZkOq3tsfr7dVL2d/3RTG39dIvFKqvkdgiPUNMM5VbG3XCemdNXMkI2jXaxDJKy
         g02g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=nyOVQ5PVOO374i50u4N6N+QA6erx4dDa+XGKhttrEt0=;
        b=L9UITIpbAhmyvt3w3HvMqvyUoF0CKOJ0DTo0EXkHsnO+k017YVNem/8mPqt6/F66J9
         kFUEtfaQ8hvoCPC3l3t61WH/Ws/i9g1S5NSJhoBe+PfsU8sHv7koY8/aXkXYEwOY5Ccy
         C9rO7tfzo/dMPeMWKdWbRXWnK4uybjkS3JRQZG8wJpE6QPuMpfnVoKFj6aJj/xvvI/di
         QS648x18I+obgqKtFQzu741bHfCjgceox6XnoDEr5SE2//FhaRqXi1sDX+NlvtjdTXFT
         MyR/FqD36RxArZjLAYCm6VQJG+hcMNSLafxCx8Yo1nfUeMZpqzj3EImKqkNkn9mk4aXo
         q7JQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf17donznIg5L12HSquB3+7m+vDLssFfT5nkHPVV5PfpoUUKg43F
	bEZvDOYc8sQ6z7FTQMPVFnY=
X-Google-Smtp-Source: AMsMyM72ons/RnP9o9Y1XuG6Z8IS26jpKEGecfG1SSTbPPGYb0aHTVL+J4JktED4nSNRb8ujfQ3biw==
X-Received: by 2002:a62:5b05:0:b0:53e:8615:37a2 with SMTP id p5-20020a625b05000000b0053e861537a2mr25520915pfb.71.1664223305521;
        Mon, 26 Sep 2022 13:15:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2cd4:0:b0:41b:c89f:182f with SMTP id s203-20020a632cd4000000b0041bc89f182fls251488pgs.10.-pod-prod-gmail;
 Mon, 26 Sep 2022 13:15:04 -0700 (PDT)
X-Received: by 2002:a63:1258:0:b0:439:c1e0:fab6 with SMTP id 24-20020a631258000000b00439c1e0fab6mr21410939pgs.377.1664223304811;
        Mon, 26 Sep 2022 13:15:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664223304; cv=none;
        d=google.com; s=arc-20160816;
        b=Eq6f3celg18bQYc7j0oQognqui3mtBPr/MXibHrd9jwVEY3uGoYcd9lQzM4uosEM8N
         AuWZXxgFQoxhIMd7AxbzBRzLlj0q0UH/mbuBuND8TCi1eSJuYWXSSIqUubEpAM2XbiUF
         DPMlgGZSGYXpBMP+H5QxZYFa6moX2X49xWWzwimiWLA7i5bl+x941NfT0BHK4VmYa8We
         2Sd9q6CzVmEVoJH8mrQRf5S99Ah5wKcseA+5yABUdJiBGx69V6+5EyJRLJJBeQN2utOJ
         bD7A4fTYVwJQyIl70Y8ZehWgExgdwbpVmJdTMfDBKwbqqdOt1WsQ7gUYejobE7haXzZe
         ISCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5e0NMcxrM37hHf1SPYvwWiwpMePVnoGZG2QjiMvl9Vw=;
        b=nDPWhBtXuTkTP3xL+FBx7g+e6NKPp4SeQkypphK7QPK6fl7RUIpIl50GU8Mznde1df
         dHEdDyqVdcfyjGcpeQIetH1No7HURRr4qwcd1B3qP2n3GeAydOjTKgh/0M/4UeGxRW5W
         rnq0xDpTM3mSf2bdizV4lDsEjeIGB+EHfgWL7KTySW6USHeOQTxNAz3RaRWNaYZvLOVc
         7NjizhQ8SHL27UJ68Xru4r+7Fbio3sOm55+ErVOKRsXxhrv3ewV+6ytCf/vZOCEviUDY
         cAv/JJU75PVeagLOzoO+OUIb8Nqsavs+rVwdUNTx0iq7kDzkXOFGXSRMuPDusWJnStfc
         zamg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=U1taE2UK;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id n20-20020a17090ade9400b002000da53a10si417pjv.2.2022.09.26.13.15.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Sep 2022 13:15:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id u59-20020a17090a51c100b00205d3c44162so429781pjh.2
        for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 13:15:04 -0700 (PDT)
X-Received: by 2002:a17:902:8214:b0:178:95c9:bd5d with SMTP id x20-20020a170902821400b0017895c9bd5dmr24334550pln.106.1664223304468;
        Mon, 26 Sep 2022 13:15:04 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id 9-20020a621409000000b0053e6eae9668sm12648188pfu.2.2022.09.26.13.15.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Sep 2022 13:15:03 -0700 (PDT)
Date: Mon, 26 Sep 2022 13:15:02 -0700
From: Kees Cook <keescook@chromium.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Feng Tang <feng.tang@intel.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Dave Hansen <dave.hansen@intel.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v6 2/4] mm/slub: only zero the requested size of buffer
 for kzalloc
Message-ID: <202209261305.CF6ED6EEC@keescook>
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-3-feng.tang@intel.com>
 <CA+fCnZfSv98uvxop7YN_L-F=WNVkb5rcwa6Nmf5yN-59p8Sr4Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZfSv98uvxop7YN_L-F=WNVkb5rcwa6Nmf5yN-59p8Sr4Q@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=U1taE2UK;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1031
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Sep 26, 2022 at 09:11:24PM +0200, Andrey Konovalov wrote:
> On Tue, Sep 13, 2022 at 8:54 AM Feng Tang <feng.tang@intel.com> wrote:
> >
> 
> Hi Feng,
> 
> > kzalloc/kmalloc will round up the request size to a fixed size
> > (mostly power of 2), so the allocated memory could be more than
> > requested. Currently kzalloc family APIs will zero all the
> > allocated memory.
> >
> > To detect out-of-bound usage of the extra allocated memory, only
> > zero the requested part, so that sanity check could be added to
> > the extra space later.
> 
> I still don't like the idea of only zeroing the requested memory and
> not the whole object. Considering potential info-leak vulnerabilities.

I really really do not like reducing the zeroing size. We're trying to
be proactive against _flaws_, which means that when there's a memory
over-read (or uninitialized use), suddenly the scope of the exposure (or
control) is wider/looser.

Imagine the (unfortunately very common) case of use-after-free attacks,
which leverage type confusion: some object is located in kmalloc-128
because it's 126 bytes. That slot gets freed and reallocated to, say, a
97 byte object going through kzalloc() or zero-on-init. With this patch
the bytes above the 97 don't get zeroed, and the stale data from the
prior 126 byte object say there happily to be used again later through
a dangling pointer, or whatever. Without the proposed patch, the entire
128 bytes is wiped, which makes stale data re-use more difficult.

> > Performance wise, smaller zeroing length also brings shorter
> > execution time, as shown from test data on various server/desktop
> > platforms.

For these cases, I think a much better solution is to provide those
sensitive allocations their own dedicated kmem_cache.

> >
> > For kzalloc users who will call ksize() later and utilize this
> > extra space, please be aware that the space is not zeroed any
> > more.
> 
> CC Kees

Thanks! Well, the good news is that ksize() side-effects is hopefully
going to vanish soon, but my objections about stale memory remain.

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202209261305.CF6ED6EEC%40keescook.
