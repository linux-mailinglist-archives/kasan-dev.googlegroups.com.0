Return-Path: <kasan-dev+bncBCF5XGNWYQBRBBHFZOVAMGQEZN76KVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 76C237EA955
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:07:33 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-778ac2308e6sf653914385a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:07:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699934852; cv=pass;
        d=google.com; s=arc-20160816;
        b=RaqdgwnjG11PbsfWS9iZFhxmapeIuTIo8K89OUlvchrAxmmrsoN2alu5xAiD7UaNP7
         12gA/MoL+xLfDLCLQpT/FIjUsfS2H7+vbSDnYT6UCC+elT01n9l8bHtza25orRcIgsFE
         DbB7Tu9v9e2O0By0hyHymnRii2LullD/m96jL54lFE/vHtW0TQ3TXHZHXy9Q085hMQk+
         qwUJUT2ZBXz/kWIND9jC2ZwaMmFBNH979mI9b5rx4LFUkbgxc61M9diIrszLSV1qSP4C
         ODbfq98IDD/XNJkAX5nj3sID1ZTFY4xbJfT9eHKaDIAuJiC8LkHZVf/8V5eqrR/3W1uq
         UeLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Zfyoa/ysYzB7YcCOrCLcCHulyySYCSageC+ALu8MxX4=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=bXGGSWRUfVgkgvLsLQlfd9+TUcv+Mr1xu53cLsFgcjXGJ3yoWkJUfQfSYI1jmDoNiP
         DCOEY2wtBzjoYlTqgnZ8BC2+ee+1VQlBRygqb67EIqJ+mcqqQNKoOnYYYb3gXo4fH5gv
         ynWPNqh7jRGe32ZS2GgXCEISZ0cpF+D9drmXprriUlBfZLF6QHlW7De8QeAAeGwLG810
         Y5oO4Bi2I+udHXUUxPXtyGjX18xABTGeNz4TJZC4YpSBMMnF8meNygYWJR33ZDGVwyhV
         U/SjfH6vwy2RrG4kkN5JUbCVupdQ0WVyhCqINq3/j+ey4F+xSy4NROVrENd+zBnEK8oU
         uk2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BRClwuEY;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699934852; x=1700539652; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Zfyoa/ysYzB7YcCOrCLcCHulyySYCSageC+ALu8MxX4=;
        b=b9PIlLBMVaMeQoUxgHEskQJ64RL+Ck01qBZ5eJZ21CLbBnA0hnUFL6VAiM1GMP95TD
         d0pQldNT8xMg5gi7D8alQTQ+Qgsmw8clJVMsCgIIjd0Y3srE1zs0I/HILywV+oGB1EiJ
         MaEzZ+6TFvvmN/tXoDoG1k9C33RcuRXVY0RtPHsqKiV3sJPm1ev/nKqtB1BBRlaP1x7m
         s3rCorK78BdYBOmoS14AyVYySIBcyJTRnLzrDxFmlsYn83yO91aOd47UkwL6p6FAzFQA
         30NEE3EnshlQkkx+HF39SvqegMmpNgZxs6Pd6K60QCffCSJ4ETitKVkfaZkFgAHDZBnM
         EsPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699934852; x=1700539652;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Zfyoa/ysYzB7YcCOrCLcCHulyySYCSageC+ALu8MxX4=;
        b=CvVXSSg7jHKfSrnTR10uszol1BY4yWqthoy8X7IF+RDhURGtXahhfJYHQxnfR/Ll4i
         twLczYskwN5nHEuQDnMpH641KqgPy8BkTmQxW92Gkjh1N33KaFe18CKslEXCvHT6hPAl
         0z9aNgXQQuhaNlh/fT3gp5QSZ1ffFmOqbhvibVZ1xWi1RJJfxhE3B1byyFglQZWpbUop
         u4MsO16bWhVoCGpmkHG1tg/xYf0FegOM5ug7sE270Y4ysfl2ezzRDk3HAgJf5ZOoHETc
         PwMfdmECy/USunyb4owx3+MrVfb3azNk2yI5OhsLGlRmWPaLcAUQDDhZOz2S90uk0GJt
         GZcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwZyEbF1VTdF3LRBXUl02QrXAgleAGix30sClWf1K8rr7lErHgn
	0AQAZ3rRNJWSIKICApXnF4k=
X-Google-Smtp-Source: AGHT+IGcUPmCvR+WxgcxNvt3uvbsWnzT9rXlIxV4IZgnpHGYyKnwOLMoUPOgPnZKGqBWB4e5OyNPOg==
X-Received: by 2002:ad4:53c6:0:b0:63f:80a0:4eea with SMTP id k6-20020ad453c6000000b0063f80a04eeamr1189571qvv.24.1699934852134;
        Mon, 13 Nov 2023 20:07:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:140d:b0:670:a1c0:e4e2 with SMTP id
 pr13-20020a056214140d00b00670a1c0e4e2ls428620qvb.1.-pod-prod-04-us; Mon, 13
 Nov 2023 20:07:31 -0800 (PST)
X-Received: by 2002:a67:e3d0:0:b0:45b:64f8:86a4 with SMTP id k16-20020a67e3d0000000b0045b64f886a4mr7758801vsm.14.1699934851015;
        Mon, 13 Nov 2023 20:07:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699934850; cv=none;
        d=google.com; s=arc-20160816;
        b=spXllGGZaLIoKJX0NDTdwqwxgbVdE820o9V0K2OuNjdg4+4OFPymooeSwozhw/upeK
         pY8J9ZE+9kMaQ/37847FaT3QyUTlmbVMVjRlXiS6heGEDUJZZG+1Sa6mYzPd+JsVxF4x
         8MYrLvvBiLqMSJr0/+LelKp9aL8+2sLtZnMqprYsFFvykpRvZbkghRRTRVHOE8IeTLQV
         uwZhKuPknjy3IeHGy+a2qhexMukCVJnOoCXfyLR/NzA8+QDuvmEPsRmXMKnYpWLctfmH
         0wXRJc5/LsHQNKrfd3L9hd2C+/XeGRIGVRAPZ1H+evfXRDRzaFBI6ixK0gp6mWYzdQ/7
         X2uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KGZDmoEeCuoU4ORpnmk9KfAQBb9nHs+S5VafgrXpLog=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=o0szXjB14cnvJ8f30NL9wggYKN+dKNGHz1AdRvtcycctQ1auGAlzZPzJL0VHIaBW3O
         8/ewK/M80ILlEY2SMY5GPtQfwz7mUTgKoWK+QIEbm68PHsNwHleWG2C7LfmSYtFtEXr4
         B26eevUZ5T6vIDxr9nc90NfxkLixoD8Szay5vDs22wwIg0Fj6xj6Z3ViyFkRv21qjTkg
         4z3N6H29Xfw6HOV3SfMORL0Lt+Jfh8qpTV5UbuB24hVxr4INHQeZUqjysK5DmTsZiMdr
         dnc8Vdc/M878y7kgU+DwChaqO4uy9zJLr7AQ0BEVL4ejyoxWcgmY7CIpkTx47Up3xVb5
         ynTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BRClwuEY;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id y5-20020ab07d05000000b007bfc3296157si571186uaw.1.2023.11.13.20.07.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:07:30 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-6c10f098a27so4031751b3a.2
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:07:30 -0800 (PST)
X-Received: by 2002:a05:6a20:6a04:b0:186:7988:c747 with SMTP id p4-20020a056a206a0400b001867988c747mr4329657pzk.19.1699934850013;
        Mon, 13 Nov 2023 20:07:30 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id j15-20020a170903024f00b001c62b9a51a4sm4782100plh.239.2023.11.13.20.07.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:07:29 -0800 (PST)
Date: Mon, 13 Nov 2023 20:07:28 -0800
From: Kees Cook <keescook@chromium.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 16/20] mm/slab: move kmalloc_slab() to mm/slab.h
Message-ID: <202311132006.51222C473@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-38-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-38-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=BRClwuEY;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432
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

On Mon, Nov 13, 2023 at 08:13:57PM +0100, Vlastimil Babka wrote:
> In preparation for the next patch, move the kmalloc_slab() function to
> the header, as it will have callers from two files, and make it inline.
> To avoid unnecessary bloat, remove all size checks/warnings from
> kmalloc_slab() as they just duplicate those in callers, especially after
> recent changes to kmalloc_size_roundup(). We just need to adjust handling
> of zero size in __do_kmalloc_node(). Also we can stop handling NULL
> result from kmalloc_slab() there as that now cannot happen (unless
> called too early during boot).
> 
> The size_index array becomes visible so rename it to a more specific
> kmalloc_size_index.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Yeah, removing the redundant size checks does make this nicer to look at. :)

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132006.51222C473%40keescook.
