Return-Path: <kasan-dev+bncBCF5XGNWYQBRBCPSZOVAMGQEC3Z22BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id A4A027EA996
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:35:22 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-7788f0f099fsf657543385a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:35:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699936521; cv=pass;
        d=google.com; s=arc-20160816;
        b=UL/upBuZwPJ4gfXhMnyVXh/460uCvCh0Yz9aikoi0AuB7T/o1veIY2ntcKoDKFzuvh
         rZHcEZNiw7aLfNAm3mUbT6YehxdW/LappjjasLNG+TWepS2OT32mGtVX9m7c1Mg6W6p7
         Vtm33Yn/jSX9l1G/QD3JNn0woQmRt7ycMBfQmMXJj4Mjrq8zRoJOSgwQYvQUV+fCP3Ly
         8YFA38GjFVVmXSWlYN3lsnkKYDazYu6/JPfskuKthq6c6o43kdeNqle76iUCUYouaSOE
         jlvSIvGZoDGZOgQRDp3dZhBYvsb4p7U3pDA28TKgRPT8HIyUEI7yi+eX0mqjpbHVPTt+
         u2OQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6yOc+3cUlSxmDs27d5pmMX+Y9WZs7aGYGkDHFujsF8c=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=SrVb401+ZVL26hEpKsghLiVXj63CkSPq42TVAr+JDRliQ0vB9SI6BrzGlnMhYGTYO/
         KuDDmuf2oxjEY7FS13Ne6S9Wl9WpXK1ceOTqd6EWgndUiQAFqi+F2wM4Sllcp5T73pcH
         RkkMInLftSfdv5QiMtEVde5V1UgCXnBZvdJ40zsRWo28ICbPqnE0qnJdGYbNi+nwtBLw
         LSj/IlswxTuZ5/nVUOHoBM3wo9Xp8w6GkcbcjQtrzz3d4QP4P//Pluaxz7o21JEfO3v3
         9EQwYAgITn0TN7m6lFyIssDkmnWu2vWTF6BUAOsU8sMPWfyLMb3pIzDyZW1HG/y0/kEm
         4fvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=NHBBo5u3;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699936521; x=1700541321; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6yOc+3cUlSxmDs27d5pmMX+Y9WZs7aGYGkDHFujsF8c=;
        b=wkLW7PYZC0T1gysRLwUy4q8eq6nOhR2OpSNb+zYOyupbwzFGW4TAQLarabrr8GRqfq
         JizBngn7PX+CQff5veaZSXl8VOwF1zS0UHhH+55WmeKK/oM9Ucojhn1cj0UkMboPKTWY
         AuUFdimW3whuPJCOqfC+IavUg0ZXELsRARRZ/jQCGlF6AxqxhBl1JKZuXie45aNzSl3b
         RcL7FXkM6QoTJ8xoP3SHoFkyHjEzpeXz/bVRUR5GSGniWgo0fSd9vZLzY9iT+KUpg+N/
         8EDY6UrkZEQkUiRyIP6jNMWCrIWMT4Ni0gd0KgM7cHHHteh60Fy0PcLxgOH0mEkvB6KR
         l3AA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699936521; x=1700541321;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6yOc+3cUlSxmDs27d5pmMX+Y9WZs7aGYGkDHFujsF8c=;
        b=TXugFw202z6ZMrc5ciqfIeTc2v7AE6spNk0ZnU5a2qmGYKypZfz3ys5vI6TVAWRhPC
         gw3OsdIRv0PfnN75erow3ftuD4QEpPA8y6AyT2xzR3zh156XzENKSutu66znmdUUDlaC
         byxuih0bjU41ehXRbhYafh6QjRWjcDmT+4zP4xF4k783r66NGzOuEfimXIdIF8MMDZzP
         GopC+gUlb2EqoVF7HZjXPtlaZW0fgs3RU0C4rXGB9J1rJfrhDRWiMCeAMA60velkhqr1
         BV9Io3G7gKHeYWJuotSP7ghzJzE/k3sXO6c5N5xda5v9dVQDBhQYlDzBBAzWS4aANTC7
         yVFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzF5/fYNMu1Zb3QKLrgw63tjvfRqTKkAWLMx0GEkiCj/qBrbILx
	v15uOkDXnnnO+8tIb+H97qOmfw==
X-Google-Smtp-Source: AGHT+IFpDJLwOi77Cf/mXazzLB9k/OdZYLd+bDEGbQZxdwmi/uJrmWKto4GHZZps4axWbioIj80n+Q==
X-Received: by 2002:a05:622a:15c1:b0:41c:c3ad:922d with SMTP id d1-20020a05622a15c100b0041cc3ad922dmr1046492qty.52.1699936521535;
        Mon, 13 Nov 2023 20:35:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5a84:0:b0:41c:c87e:86cf with SMTP id c4-20020ac85a84000000b0041cc87e86cfls1265103qtc.1.-pod-prod-04-us;
 Mon, 13 Nov 2023 20:35:21 -0800 (PST)
X-Received: by 2002:a05:622a:10e:b0:417:a974:889e with SMTP id u14-20020a05622a010e00b00417a974889emr1445565qtw.2.1699936520949;
        Mon, 13 Nov 2023 20:35:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699936520; cv=none;
        d=google.com; s=arc-20160816;
        b=T8bc72lO6erA9f4czWj8QrfScM/iGkXNKlwH8uFUD1sF3wGKjds0OMlp7GYx0G8TsB
         4oQw+RnXfSLC4xQpUBiE0IPfrTFoYwyzP3+lG1pCyAhlj7v5S8D5MJcvy+hXCzPpz91u
         DVHOSJZ36G6C14B7RbITh3/yMk1t+IyMdh3lIuDQ3KuvpBHVGHpAdEXI9zbhaRdlvel8
         u3QlAiGZiluu9CSHgWUYzOkw2BSmBHEOftUrjuGiHc9q5hkol1RgW0qLXlJtw8EMXWrc
         a16n9axOqwr8g65on4ndpWC1H5CyZlzGTtAVAbAKD40l/Y0DqsBvMY8gFaXYxGZ83l8o
         +/CQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=2qJn7DbKeJdLYDJu5dncSAZYv48TYbHL51nKAxUFFOc=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=bOv+lamGHvmKNOuvcYcR/0PS1vOf+PDmd6TOyy4Esh1PmCFVTZSK/px891++wM1H1d
         pak427wHBjddAgiCOKWpvrcGmWHDOi+XrWyGNo994xCsAKoVMUfbfZFo7NcbKsqP8b4x
         XWGHtBJm3t7O0aVdbW0GoyqKArdP1Fzvey7LHHrB7tBc6/MnZqn46FvFEuSL9Ib6HP6l
         A5vxxpXN2jqjbmIzfnr6lsfcj+ii59OhX2punGHOdH2k48qFjBS9tMV9/riz0HKmzj5/
         6NUIaNUNf44UEGd0AV7FTySJuLLqqY5QkMdmWB7QYMpJxLf97ClW5vbA5s5zopSgx+RD
         HIfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=NHBBo5u3;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id gd10-20020a05622a5c0a00b0041790471199si922143qtb.4.2023.11.13.20.35.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:35:20 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-1cc2fc281cdso39221845ad.0
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:35:20 -0800 (PST)
X-Received: by 2002:a17:903:11d1:b0:1cc:6cc7:e29f with SMTP id q17-20020a17090311d100b001cc6cc7e29fmr1410299plh.43.1699936520572;
        Mon, 13 Nov 2023 20:35:20 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id l18-20020a170903121200b001bf52834696sm4762331plh.207.2023.11.13.20.35.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:35:20 -0800 (PST)
Date: Mon, 13 Nov 2023 20:35:19 -0800
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
Subject: Re: [PATCH 09/20] mm/slab: move struct kmem_cache_cpu declaration to
 slub.c
Message-ID: <202311132035.A0F72C0F5@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-31-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-31-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=NHBBo5u3;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636
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

On Mon, Nov 13, 2023 at 08:13:50PM +0100, Vlastimil Babka wrote:
> Nothing outside SLUB itself accesses the struct kmem_cache_cpu fields so
> it does not need to be declared in slub_def.h. This allows also to move
> enum stat_item.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132035.A0F72C0F5%40keescook.
