Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD5HWK2QMGQE4WXVAYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E0469945985
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2024 10:06:59 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-52f00bde29dsf10467233e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Aug 2024 01:06:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722586001; cv=pass;
        d=google.com; s=arc-20160816;
        b=y9mar2IyB3S/Y17tyThZmErZkp2dl5T5UNN53ijwmkF8UWevsg6gbnlPw4qifVfXB+
         XA4uXK/2kf/t9IkNksnicU1MQBP7ARxAadavv8WocVeMa5Mv9xgTgclPMneTS23n9Fm8
         SbmLN5Mo6Tmil8ktUarFuQKo3BB7vDVCPXUyrzz91rwOV6ZOERWtVcsGu7DaxoJARYcs
         +MZOjYTLZbWIJZZMGIJdXn52q2+842idjZAZEQsRrOJfRuQq1cZ2FhWaOzEPN853rzH8
         yuvg0T1gSQ+X5s9JzL9BoMo0LhDexA9zAiLBtY+CXFp5pfY3Abfki6T30K+X4AC9BGzX
         ypew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=q6kZ8l52X3PAmLQmnriqzdSvk/UXzjpWH3Jgj5fp7vg=;
        fh=VJSMQCigpAWIqM3q+/Kor0nf9ukuNIam9J/VSZBEfR4=;
        b=PKmxCNtFv9uFbbZXe4DHdQF/iBLqmb1bJNadMD/r5i6d7YMhv9nJsKFirgb3ptoJhv
         wn5VC9o3GhueZh1Y6pFETTUquP75PNDane1QNVBcvGHTuNloiO0rG4c/0Uogae98RCdw
         bZ8l9SiUR/pNihwl6Nec+xfH7kfdiezPxpxXFI8Wsy9gn7VVne+cbdo0D3Vj6cwvMvA+
         lMdZ3JlKmAMxeK545Tt5/LuaLAOrzfKpU/r2FIHk37lJUA+nIHP6N8cW2ULAAo+qVKgW
         QDAE7sHeWQUl2unLBtJ7nkuneiw1E4UnCl0lSelO211JSDaUXMpFhZW2GxRu7ggwKyPq
         cz+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yJj04GUx;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722586001; x=1723190801; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=q6kZ8l52X3PAmLQmnriqzdSvk/UXzjpWH3Jgj5fp7vg=;
        b=kNDZvnSPLW+Q9n1WUJVqMUMGnZvKtj8laVZ68fN2TZhsHe1ZaZiNCSiMWrbmOGhL06
         kYW1yVqV8slIwO92xoTS+ZW/WNHyWGd20KdqDqRanEp765I657YxuB8/UGaRhpkjc2Oy
         ZNofKXQe1poTQtWtNtuMse8aPEpOL67IESqqlCpTLiKxD4dWLvWXGna2g3+eSz4IDPaw
         8fKxY00rgoBvDSYd5b8XSoR9K4A4LX4SgoG17HafH1EY/okTY2khl/5HYbWJf0P9xg22
         VX3uubgTBu+aI3VvQTYLdYED9We5lNXlSE1zMGEGYhnIHeoo23WXxTvxG2Q0et4z+dX9
         VcjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722586001; x=1723190801;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=q6kZ8l52X3PAmLQmnriqzdSvk/UXzjpWH3Jgj5fp7vg=;
        b=HXaJzlSnsvxvzy5feGYrKIFlvpIbkrZk1XFsr3SSnIGaG9qZBTbAKbi2S89cRybnoZ
         Bnf50chYNdlbwgALabo3n9CxU0THpVeYL3K/Ardic4LzWu7ZW7tDNPPUg4ZiyBzFr0eq
         AZSlL/eYYafaPE11x281cMO7KudDzHW306HHpGKr+PJh72pC2TKY1pYJWAvIA5F0wVyO
         Labx0/857S1m8lMgToEduc7JB6wXdoZwxZ2mIZxlsqwGGFuJREpaKdLTMJ+C3UTCuvN+
         zBRvk8+4hmc3u5vWAHCmJeuksRTJ3+VtcZPFHcwzAMt+8rCYg2ggRyT6ks9t0aFXgwAn
         JjsQ==
X-Forwarded-Encrypted: i=2; AJvYcCWycw8tjGTBvLC4G7StV8kiBqLe7f0vGNkdCOQ1+pDA74+OxFWS5QoEBlouq0UUiXuA2KFUDpDO1LUf/rfnqyeYOw6e+X8oKA==
X-Gm-Message-State: AOJu0YzUCiXRJeN/tIZ+ZAYwoPWMHgmi9u/E9rps6yciBH3YZX7NYav6
	0p3XhNl7N8YyXJnwQQ36RlV7VFFKAaWIhDvdZ0KTzkXEG8W30wqM
X-Google-Smtp-Source: AGHT+IHwI2ItoANBRNG6mOJvW3YxS/2hAxXR1KlG8QA3fGnvXD/UjltOpRoc1M1aUwhCTe0dbweXVg==
X-Received: by 2002:a05:6512:eaa:b0:52e:7df0:9a78 with SMTP id 2adb3069b0e04-530bb38db9dmr2357645e87.32.1722585999812;
        Fri, 02 Aug 2024 01:06:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b11:b0:52f:c9e7:c51d with SMTP id
 2adb3069b0e04-52fd3f462afls4205779e87.0.-pod-prod-05-eu; Fri, 02 Aug 2024
 01:06:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX0OJDzqswlr132fjIELWV4OhebHTb/UmKhwv3yNfjNnC0zXWAQY7BYzip3lZa3HWJtIIe/PCK1YURYhpeXdBguRX8ddDte9IewnA==
X-Received: by 2002:a05:6512:220b:b0:52c:ddef:4eb7 with SMTP id 2adb3069b0e04-530bb38139fmr2065386e87.20.1722585997338;
        Fri, 02 Aug 2024 01:06:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722585997; cv=none;
        d=google.com; s=arc-20160816;
        b=o3J8WvZm894cEnUDY8jG/KR+gtcs5YrDXnXqTEP1v8pnHbopMbq262mafaEw1sdwXt
         4ld81AWy3HJypj0QBl2mTS9yEZAg3+OO+N5yiaUUijfeEo5w0bVQBlOI0mQi1HaWTHqF
         dRWoNX+nc0Fx4uKSW/uuIk3Fy5vmEIknxHY0acDIVbDHHDxZarOvoNJJU+deUN+Gnl6A
         4tekk02BEwaybAY9Jx2plFbh+54ym5qLepozDvJcZ/2fOjpmPG9sJ7X14YidRyKim11C
         xxx9FcvUpuGoNz74MimRStWl4oGN3BSH2nC2CO63eHgcjVywsPt9iS9GBdpqvgfBeYL3
         3OUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5MPJE7ezvPCHFVJoWU7UFGAwm++u4dc+Z2RK0PA0V7w=;
        fh=bdkCLSj8ieEo3GPdPuLD2YFb7WNZMctBW1lXIl/NtCc=;
        b=HHkGftbnXV+wkn0zGojz3TaE/NLf/F/Pc4KIwGJrbFX9qtqktexcltpSsLPSkYpsAm
         d4gUV8BiIgNaImLH64kImwmzAXiyf43SklwuBAHB+J3Gne3tZgi6Vu/ZgFDx29dNAf/J
         qd5xECyKua8el/kuzjHv2K2s+yDg+5G+iuH6MH34OLZ6IbY5XqbX0nJxoV+0nx+1P5OX
         LhVguzbccciNRgMbKjrgDzqBl4vZb9fHMcxk53+XFue+dFmDPkfnE2XHQ9M8SRw17lUA
         m4w79F0+adWtcoPIYTrPuXlcAEaRmeZKIlfzMCB7RJYSCReJ/eugoHQTESRQQrJoQPqp
         iWoA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yJj04GUx;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-530bba270b5si29965e87.9.2024.08.02.01.06.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Aug 2024 01:06:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-4257d5fc9b7so69070785e9.2
        for <kasan-dev@googlegroups.com>; Fri, 02 Aug 2024 01:06:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUZ3xPXPuNHfiGavhbTM/f/7qkqmjODH7zwawANwmBybjLEqwb+Ip2lOSXIZK0YTYXigSJQstgc2O+tZMbkp9rZe+lxuEBdCOxikw==
X-Received: by 2002:a05:600c:4588:b0:428:15b0:c8dd with SMTP id 5b1f17b1804b1-428e6b2f14emr22464585e9.20.1722585996403;
        Fri, 02 Aug 2024 01:06:36 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:6639:aad1:e65e:e31a])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-428eabb660esm10591795e9.31.2024.08.02.01.06.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Aug 2024 01:06:35 -0700 (PDT)
Date: Fri, 2 Aug 2024 10:06:30 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jann Horn <jannh@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH v5 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
Message-ID: <ZqyThs-o85nqueaF@elver.google.com>
References: <20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com>
 <20240730-kasan-tsbrcu-v5-2-48d3cbdfccc5@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240730-kasan-tsbrcu-v5-2-48d3cbdfccc5@google.com>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=yJj04GUx;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Jul 30, 2024 at 01:06PM +0200, Jann Horn wrote:
[...]
> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +	if ((s->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_delay) {
> +		struct rcu_delayed_free *delayed_free;
> +
> +		delayed_free = kmalloc(sizeof(*delayed_free), GFP_NOWAIT);

This may well be allocated by KFENCE.

[...]
> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
> +{
> +	struct rcu_delayed_free *delayed_free =
> +			container_of(rcu_head, struct rcu_delayed_free, head);
> +	void *object = delayed_free->object;
> +	struct slab *slab = virt_to_slab(object);
> +	struct kmem_cache *s;
> +
> +	if (WARN_ON(is_kfence_address(rcu_head)))
> +		return;

syzbot found this warning to trigger (because see above comment):
https://lore.kernel.org/all/00000000000052aa15061eaeb1fd@google.com/

Should this have been `is_kfence_address(object)`?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZqyThs-o85nqueaF%40elver.google.com.
