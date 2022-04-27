Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3XWUSJQMGQEPDBQUHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id B4965511802
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 14:47:42 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id ay39-20020a05600c1e2700b0038ff4f1014fsf699082wmb.7
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 05:47:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651063662; cv=pass;
        d=google.com; s=arc-20160816;
        b=iPhUnmypmnwV2gEJMQTmCatav39WLX1oPQJFo5Vpl10TsjdrdWTHAxXbKBUa0EAB4Y
         yz5ugFvIHFBICdADCyRQ9JoYagMxOxE5uj/zqcsYGvMdPwY3n47hqybeSUAxLBhBh/jg
         rWNtwGLGOoCuKHUyT4awRGF1gcTDJ91/wExcXQ67h4S8WFS52062XhOSC9WO9a1k2b8D
         T/iSXYrCPFnkX9JvJXUHWsSuQiWrzZLqCOMdGWcYN++RkYBrKCfa3nlPuu0LpQcZkpXi
         vHbUlNAuSAew0csgLobs62v6YEJeOOu84Vkw0WA27vLCN4umUunfwKcmTzLbL3OMqiZL
         BHMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=pJb7aNU8QtBvEErRfH4dJRPivIqn7e851njKix7ehYs=;
        b=e4nK27Eqc2quhG+LapNUAV+HwIP9unwZfeP9lPT2u80cOnUWA9JQIhsUc2q5MhE8Zn
         bdg64EunnSXsX6k//5wFMt961S2VQp/1af9RVHa96JL4o/aKQdihS7yoYW7zGX+3oyOc
         XPmzPAIwaFDahTNv2NbGjH58xE4AGsv42/kpetgy7/IF9FhGrkVOVl66SLKSj3OGpxoJ
         uI5c/iD0fhkiY06eRLUhGo0c5CLhYoXve1dSPm/iomPQzDEEJzsc59fpB1qV7LDGH3hr
         vboCDP81ZvMiB3zI5QkIlK2GQIdIBXOUnb1+nbzdqRkfDDSkhNbRiFWqD4FdUXTocObV
         BNSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IW2c9joH;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pJb7aNU8QtBvEErRfH4dJRPivIqn7e851njKix7ehYs=;
        b=mfvWtDATq+vsbo0hHcqiVQtlxRWvaQXqKLBXmRzOJCfh75Yrjcj9gViJeRnAcrEjp0
         S6guRaBqIHVzh6P3zUlxUOMg7XzA09A4Nanb6oeZtDtCKH0b7BlTY0pLqEDDg0ymxn92
         yTcCrA7NPdwWgGErSXwwXbxKMGLjEMc3OzjYkCwSvNamYAaDlsNjnXR9O0KDy0H20ErJ
         4n2D6IowCZEku1plUo5RmukP1R7BBZAEPcciP+YkUyH9ch6EL+bcofDRKmA0i/4MDaGf
         TX2qqm+37U3CLpQwc0mUOCDBunXPWN9WVlygzW+CNcUKrf5PspMjA+JddNMVJS7aqQNK
         pJfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pJb7aNU8QtBvEErRfH4dJRPivIqn7e851njKix7ehYs=;
        b=73YQE7eoXGEBRLtqbT89gycWUCV1COZfNZdQRtdXzER0YG3n92INDFov1m9TzCIlm8
         Q7ChlNT+1UuybJZs+hFkdNQnd32o+mnQTmMG4v+f2dGdthiHRx0UqxN//Z+inEvyVwUZ
         4FdGqGoC5B/KSJLATB7Axgqm8HM7O9ZrUCJ6KrQRAcFj/tbqEBx/ur7PLxyNnMnli72W
         vliAGQI7ndteX3sxeC3IZS7L1tLUaup2mINCFUGAfjCYdc4bc66nfLQAgnxZ9HfpSoQK
         GG8n/sqR1WI9Rf3JrNhsIq9fgA0SvqKQRdCnQCb86RhUpcRiZmoP7bBMS67sjVpmwWYu
         igxw==
X-Gm-Message-State: AOAM5316jW64dSR67S1nUemMYw+FmlHL9QyIKB4/7k7LNV+iVOoWBNf8
	tkVC73ha1xk7FawrQIhUNLM=
X-Google-Smtp-Source: ABdhPJx1OXZPxQXEI0bJ2SqegcFnWkeN+NFjzFYHOwrEMD9Ylz8l17umHaR6L9yrUog6jXrzshr85w==
X-Received: by 2002:a7b:c24d:0:b0:393:f9a3:e712 with SMTP id b13-20020a7bc24d000000b00393f9a3e712mr7470796wmj.198.1651063662553;
        Wed, 27 Apr 2022 05:47:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f42:b0:393:edbd:e7a5 with SMTP id
 m2-20020a05600c4f4200b00393edbde7a5ls1014268wmq.3.gmail; Wed, 27 Apr 2022
 05:47:41 -0700 (PDT)
X-Received: by 2002:a7b:c5d0:0:b0:389:fe85:3d79 with SMTP id n16-20020a7bc5d0000000b00389fe853d79mr35456334wmk.77.1651063661380;
        Wed, 27 Apr 2022 05:47:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651063661; cv=none;
        d=google.com; s=arc-20160816;
        b=IgVeug69x68ifo3N+GaP2jKVVLOMnQb48zvOoNs8+XOBr3+CNeX5WgEBXHIyO034bn
         XvxFI3r7m9r/JpfE6QI6AqACVYCrS+UDuNrS1kijKq7s/SMuiRhHE/kr6TLAicGB6JwG
         fbp5Jr44t16+ZlYO1pz/4/pj83NwEOb6kSVokcXApvteEKff/KH1/TMmEataLSpqOvCK
         jL7pCd3niXUrkoaAzEDQfKEBF+AViyJYoi76iDbOhuE4vgmqYdpOqB1N2qO4n8uaKv+1
         KLAasqX4cUWJZyOPTogRuzVtPZQJwsk2EAcvTXLFiYcy0o+wCMQiGyfTcEAFh1p007oO
         jORw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=4ZU7ssA0uBUIH6XIuoYvcPvJ99ZnRQPUGmPQtpNi76c=;
        b=VdDCbwo94Cl+U3uSeEYKSEGNYI1Yeiu8fCkmhwiZ+5H/l20j8uA74DfRVPViyvIoPq
         r+RkyCOqLw62wTjXRkE/ABk4q903IERboX78+cAI74UuKX/SeQSHzEQm5ExEjJoTubPt
         uTRQ9rPI6Df+rFwk6ZWGUm2dkgmE/2xZ2idjFr+4kQ4sdn0Uh2pbLggIMRC5FT+4qQt5
         EErX45bskKEDTI5S4N8sIWxotq1wKX878FRJZT84GtzQuhrnJTlyqDA0s3gUDBBDweaZ
         VK4cR7KzztQ8hnJrTgJSAWN07drX5rngJgz1UoY6QOIEJu/dkFAEIVpFXyrf/2MAhC4T
         Ql3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IW2c9joH;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id o9-20020a05600002c900b0020aa8063034si73786wry.5.2022.04.27.05.47.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Apr 2022 05:47:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id y21so1090749wmi.2
        for <kasan-dev@googlegroups.com>; Wed, 27 Apr 2022 05:47:41 -0700 (PDT)
X-Received: by 2002:a05:600c:1584:b0:38e:c80e:b8b5 with SMTP id r4-20020a05600c158400b0038ec80eb8b5mr34457739wmf.99.1651063660964;
        Wed, 27 Apr 2022 05:47:40 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:493f:cd0f:324a:323c])
        by smtp.gmail.com with ESMTPSA id w12-20020adf8bcc000000b002060e3da33fsm13564171wra.66.2022.04.27.05.47.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Apr 2022 05:47:40 -0700 (PDT)
Date: Wed, 27 Apr 2022 14:47:34 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Matthew Wilcox <willy@infradead.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Vegard Nossum <vegard.nossum@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 03/46] kasan: common: adapt to the new prototype of
 __stack_depot_save()
Message-ID: <Ymk7ZkkIq6rF+BmI@elver.google.com>
References: <20220426164315.625149-1-glider@google.com>
 <20220426164315.625149-4-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220426164315.625149-4-glider@google.com>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=IW2c9joH;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as
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

On Tue, Apr 26, 2022 at 06:42PM +0200, Alexander Potapenko wrote:
> Pass extra_bits=0, as KASAN does not intend to store additional
> information in the stack handle. No functional change.
> 
> Signed-off-by: Alexander Potapenko <glider@google.com>

I think this patch needs to be folded into the previous one, otherwise
bisection will be broken.

> ---
> Link: https://linux-review.googlesource.com/id/I932d8f4f11a41b7483e0d57078744cc94697607a
> ---
>  mm/kasan/common.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index d9079ec11f313..5d244746ac4fe 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -36,7 +36,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
>  	unsigned int nr_entries;
>  
>  	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
> -	return __stack_depot_save(entries, nr_entries, flags, can_alloc);
> +	return __stack_depot_save(entries, nr_entries, 0, flags, can_alloc);
>  }
>  
>  void kasan_set_track(struct kasan_track *track, gfp_t flags)
> -- 
> 2.36.0.rc2.479.g8af0fa9b8e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ymk7ZkkIq6rF%2BBmI%40elver.google.com.
