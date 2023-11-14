Return-Path: <kasan-dev+bncBCF5XGNWYQBRBHPWZOVAMGQEJZ6L2GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id AD3297EA9B9
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:44:14 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6755f01ca7dsf10432436d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:44:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699937053; cv=pass;
        d=google.com; s=arc-20160816;
        b=c4vTG6ywyDXtCD/nIRZl5FHBam5JH82tXv/YqJLz2ezUEuXjyIQUGZYigHNjPnNGKn
         6/6PreXuF7vpZ4eErFD+llA+SKzxb+1+3y+q5pbOYrs2WgcomfVYT1gUnCUnLnR+ahTI
         h/9kPe2jESZ/6qw/KNSP6OLN+O3zgfTucr8jt+ljZrtdaPTA52Oz2lus1bvjDzaLGldm
         kitHvzLtK6D/+af9ba2dRXK/Qk+BjVy2UVzT1pgp7bI1kwBEu91XazQxWAmZ+cmCYMhO
         2KeAiA2NzqTs5Zj+jA5ZoPVcS5/nee4trWNJoTzkG371cfWBK3GpIp2yIfRYZc3b8UNM
         RV1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=PZv1aLioXQzygOwWLCusZFzHBSmZqXgqn4qCrg6WCGg=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=mdy17W1C3Wov6D6Pj0a7vYWYTvNOS8HX6cyLth9Gq0saXzpt6njZ5qtxf9CHwFUd2S
         gsl6HVkHQX9uIxM30kpQj/NOhjDJHhxvdSqfYFVtvhWP4hHCXArR8w0J2/vK069i11/T
         kcnishUcWNdDKPklXYrVC7TbbKyqG0I/0Bi/U/AGcebo71Ua9J0v3U27CHjrdROt/D8q
         cGDy11Ywo7AmSUizF2aojJLYF7MeLLcap9dhQF1D7daG/Tr5xo8BFVw/GiIDVSeXl61M
         rN+TD0w1lTdbjKDK+eFuCyQGsDgSIU+n40n27gSQ7pkr69I/h0nRp03I6m8OkO1aiH4c
         9csg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="T//23W0r";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699937053; x=1700541853; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PZv1aLioXQzygOwWLCusZFzHBSmZqXgqn4qCrg6WCGg=;
        b=QOdS6x4AU81IkaLHINKNhYP9N/QXyExNtg6cpAatpXhRoBy0u7BWvnMOUF07nOxpHU
         YgzYnWklysjP1uAKKdd40LmMmpNRKiD0yC+PZ/LlYgdEsvgiyom/rGM0M83hjawn4/gB
         WiHgDC3v1lOr++djmmbXiXFYGVDPpxAAD67i4/UZDhWOtgM+tx5FfujtXNprrZFhhWKZ
         P39k/mio3l9BKr4wv14OcbgqGUXvnHa/HhNkd9XjcVIyYBqPh2/kPpwsdylEri0Zo1o8
         pYeI6RquyyaxxjwAjJ1YqMS9YyDq9JTU+YNIyIF7vK4vGubVDkyIxNuHQRKvul/SwuIW
         XYTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699937053; x=1700541853;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PZv1aLioXQzygOwWLCusZFzHBSmZqXgqn4qCrg6WCGg=;
        b=mAQxkNmQzZqIP477dXOGEleI1tIqodbJK4p4VflIy96g1evZf6+a1pCEfJKEttPYSt
         ZegSkKIbgni4r3m/muWKA8iT16ji5iCFYMd9o5uvVQFfDOYFF4dzHp54u4asBmHpDTm+
         yV8mJKt4tdWTfYxUXaTJf7XbEHwewqEGQLKV5vpth+AaasIzOFLwYDcj7Wgwn2+VHWif
         xNWCs+s4XH1PmigbgeuG0lsf3giyNzFHYUui939N2bblANGoG0hnsgbRtuKo6IXxDLAD
         jRqAMKdLLsbH69wnMsX5qXT+MsbxgGUOb24pYHvHhWUo2JUxw3cubvsq0i+V0p+m+hAI
         QsOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxhlI32jXE0yRRpCqMQwW2BwYO8+98/r/4Sias9FVjVYjAxEaL9
	yJPqPLO/9A64yxqEiQZ9JH4=
X-Google-Smtp-Source: AGHT+IEmh4Uv/9EgJUZ7NPGtMBdpMHtpLTryHFb19lKMnGFa74raU/wb9iM/QqHCiE4CzhzYVIh78Q==
X-Received: by 2002:a0c:ea8e:0:b0:66d:6111:5c5c with SMTP id d14-20020a0cea8e000000b0066d61115c5cmr1262744qvp.3.1699937053656;
        Mon, 13 Nov 2023 20:44:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:140d:b0:670:a1c0:e4e2 with SMTP id
 pr13-20020a056214140d00b00670a1c0e4e2ls451612qvb.1.-pod-prod-04-us; Mon, 13
 Nov 2023 20:44:13 -0800 (PST)
X-Received: by 2002:a05:6214:5804:b0:66d:2aa3:cd49 with SMTP id mk4-20020a056214580400b0066d2aa3cd49mr1291716qvb.14.1699937052994;
        Mon, 13 Nov 2023 20:44:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699937052; cv=none;
        d=google.com; s=arc-20160816;
        b=Pt/BN2QUnQIBa3KK7MEwZXJtOtS1sru4SP7hVxzQ+wBz3tnnvZm+6is/fCcJWfZilu
         Th3qUShuVUygE/S5QW0OCctqsgDaJvBj2pB6hEmnQ6V7IB8KhHstkJwSBfM23Vbh2a/4
         /kvvUF59BH5qQdQunUAIsLS7LfCZ65VCveX5dBBHFgc8Lvae5ExdOkiuIYCP97J4xUAn
         VJasu5y+cfPhUOx2x2nlnz+bz0V7hD8GnRuBec6U7fiMp+F6FczzAjlKwzG6ZQwwRYjn
         ibXBS2t+Qyfc37t/koU1qEU4xr77Zcft9sgbcrRwXKSO7bjtIHVDiclPD5JhjNz5xDyx
         i2lA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6ONkBbb+HnFKyr5bwkUFFQAkj5jFzRIolELIrPxQNcw=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=huV58mHxDMd9hWM+sZFSQ9kmzkfQyH8mFqzMACKipcNoioBubtP9NOspN0aXsiINCq
         dsq5Cq8R99qLcHEsjfBSop5blZnE+SG4HwOUiMfN9Nh8pHhV4K3j7BFTEot9W/E6zGc0
         N8j/c3TfjPCwGAGrbGUOv3euoG3qR12ay7JD02WRWKbuAyoXQdObihayD//7chJ3BYLC
         Ui6xuNmUb6dZPywEWhKAfzJzXFZsojcoJmsZK89SgfSf8T3bYKsuXvetFHBK69K/pFAE
         P/Ukfx39aI0dnN9SBOrRIAWBu3MEDhtoIXgM+gZ5d7b2c6sEMLj8zXjcx82pACb+IxFi
         ABFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="T//23W0r";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id p5-20020a0cfd85000000b0065afe245389si563624qvr.5.2023.11.13.20.44.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:44:12 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-6c39ad730aaso4064777b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:44:12 -0800 (PST)
X-Received: by 2002:a05:6a00:3a1f:b0:6c6:9b11:f718 with SMTP id fj31-20020a056a003a1f00b006c69b11f718mr6590354pfb.4.1699937052092;
        Mon, 13 Nov 2023 20:44:12 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id b22-20020aa78116000000b006be5e537b6csm389373pfi.63.2023.11.13.20.44.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:44:11 -0800 (PST)
Date: Mon, 13 Nov 2023 20:44:11 -0800
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
Subject: Re: [PATCH 13/20] mm/slab: move memcg related functions from slab.h
 to slub.c
Message-ID: <202311132044.C7D682723@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-35-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-35-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="T//23W0r";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b
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

On Mon, Nov 13, 2023 at 08:13:54PM +0100, Vlastimil Babka wrote:
> We don't share those between SLAB and SLUB anymore, so most memcg
> related functions can be moved to slub.c proper.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132044.C7D682723%40keescook.
