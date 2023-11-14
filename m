Return-Path: <kasan-dev+bncBCF5XGNWYQBRBLXXZOVAMGQEXJM27BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 990237EA9C8
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:46:39 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-670991f8b5csf102494986d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:46:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699937198; cv=pass;
        d=google.com; s=arc-20160816;
        b=uXM3rm6N0bSBwSVATTk7nsjygyQyYqRXzTf1u5P2cHWJIfhWMExh8tTBp807L13bkN
         6NWAlImqKiVkwCCfP8hXeX6dUJLkbllSi46Qe1YbbtuHoNohPr+xbgYflBax3NN1iSt3
         3pbrnMUJi8tYde+WQksfuuoKz6fZJSutOJC9s57d3+3ewRLUd36DA3zXx3lAAv0S8QY8
         S/vWeQFCh5c+0Tnk9o2CLysYs04Z71TrVts2HEyRo3N8eov9PhqgqxKidV07cRfu0+pD
         vcJxxisGzxo1bt3xrkY4jLgybR3ApEsDDIajzeOjuwPB8zTwSlYNJtcaErF5Fh2v7oFF
         AhHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=djI0uxWx71KxRNSiuizDkxpsnHGRVh6Y2uiHzZxHyks=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=GrJB5n+ZSpHsWtMOFpt9oSobyfH2Lh5eBYaGzebE5wiEqzWH6G3XCERGoW8R38f4pu
         DNGqDdc57dQ8R8XSSrzZM6OC6ltFtw/iT/1CaTrvz+bYe7zCRIZZ4G/QUVHQ5N1aZ7Pz
         MS79FCEeK9mn7G60qTxqQHMxQPAx5QaicHRbJs1LUAcDWsBXjYbGBVzRaHjXHd6dRWRm
         5AjMIZlQWGtwcpBVq07+5svZOrkZ/Fj+mWcvArQZRaqPamYz+RwA2kJZdVyYzo6ms1le
         sXPf47DSOfr86SwW100l4nTW5BbdwwlPWTTHV/h9HfKcBzb5jSm2Q24KcD/TwrjqSond
         tO+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Hg3CZyEr;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699937198; x=1700541998; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=djI0uxWx71KxRNSiuizDkxpsnHGRVh6Y2uiHzZxHyks=;
        b=Igh/+4/HMOuTRWp9OAUBWTX8fCKk2Tn8ulqxKIStiFwrfZBoJEqMKHH8rMtBF9ahLB
         H0zzXm92pvR0cIC3SyqRPPOmNSf9ku5CX1XK+vFjwKTGVLkONyVrGGhs9H+/WGmg9a/l
         NZob4xF4pPGeSm5/xlIA9QrUmtUyHDgYp4s6oPpuBaZdXtLexF2eqazZaBmU/LSgOhLe
         Nb8Syiw4ny6fQx1SklhFksU75XNIu748ufl3xzHOABS2J8y9YjX0p8RDX4R2lHMGWKnz
         mVnriSxChX+2NV86FWQVzyoBeQtLKSZB7XIWOxc0EwwpfaaezLqrHngU2If8qwyZaLde
         FnOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699937198; x=1700541998;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=djI0uxWx71KxRNSiuizDkxpsnHGRVh6Y2uiHzZxHyks=;
        b=Bdjf+6qGBnqzB4/CE3RgGF4nj7jD7O0/qdjxo5z4uQObQhQNpBTYtIkXMfpciIL04r
         +09+kTEvlhfgoyZ3gLTqR5p62rA0tVjIYniS7m/TGcHtBUmsv9LM2T9j5JI/rF+2kRNF
         /b/yCWioVcxSF28QQxr+W+vEt+Do8vtJgzCzjgkR6HeUplUZx8VMlGe//tbr76czd8Ww
         Nc2n07CAcpn8bzI/0wE5C5lLoH9IlaEyUEmtif0UyZQsCNQyL9XCmaLm9sRt3LWW7ei9
         3f8aDASDrNdysTBvXtWl9yla8UMoE+ksHbfACnfdwdUiyArJO1g018YfxhHUU522bPLP
         Dobg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywg1E7y4EJLOiJKdYNfl/LfJStJIC6cOpFugWeTHUkU2mJEjnUl
	lX27SjqJ55HaB0gRcQIwlZY=
X-Google-Smtp-Source: AGHT+IGwzpp9vogGUnFZ+NDy97cZjRdrz1cP+Eok+NWORf1YcooPkxg9OCEtatNTKHPDjC8vwQnq4w==
X-Received: by 2002:a05:6214:5592:b0:66f:b7ff:1e12 with SMTP id mi18-20020a056214559200b0066fb7ff1e12mr1943423qvb.20.1699937198440;
        Mon, 13 Nov 2023 20:46:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:45ab:0:b0:668:d9c1:f577 with SMTP id y11-20020ad445ab000000b00668d9c1f577ls3367536qvu.0.-pod-prod-00-us;
 Mon, 13 Nov 2023 20:46:37 -0800 (PST)
X-Received: by 2002:a05:6122:4998:b0:4ac:e85:8bb with SMTP id ex24-20020a056122499800b004ac0e8508bbmr905383vkb.6.1699937197471;
        Mon, 13 Nov 2023 20:46:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699937197; cv=none;
        d=google.com; s=arc-20160816;
        b=RMAnX+YWyn5swM41XpgAuZYB9kmaZUYIhwv+cX+ISyYDmpi8a66RDIdhrI2bq5ZzIx
         ywN5qvrg8/wFtYqxT+iAWkdUV1VLZgjmPHeYdyupXXZ69WbPQWR5z3VPp4j1jnPbJEol
         OYPB/1LuXqLmEROAWpU/AQgoX/xaTyrjN5iblHtg9QDw94TVSJGTCHdBloHJKuKEO1Xm
         AuBRaM7YKfRmuuquNC1yVQsz0clg6Admvp2YcgknS9psHhSmwXAg5dkOyiCE6m5Kniwz
         krqYn5bOpCy3x+wgS4+1fdSDx/CjmALvn/kfbfc1wC1uCli8EuU7Wl4X4EA4+5Kv5jJ9
         j3VQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=z0a8u4z+DUq7pMxicKnRyBLDUEkYlUYGe8Ef1Qv3STI=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=DwrLiKZToJOsnHW9+5CVB9zK+YVmAUBiYNtLEuIpHtvN7sUnWWRlVr2uAwyyoOyDDQ
         Qdx5EQUR1K1DrfkMUn0oYgDXp8/U89GY4S3eNCybeas6qgExD5hCKiObzFRnUppGskw3
         WXhqb9CMX/nkNbRr0gDOdIniMu1fogwSEFJlManIiN21RL9mQEZAdUy3vYOAQK415N1l
         VlLQnVaHUXVapv0JUO0zBaYvNPcFZEynZpmfPZfNktF+pTMsdt4k/b3/RxyTa8T2e+YI
         k/6Bs7wpzc38KG6DPyHt9s0K2Yd1yV4K+NTw+vTy4n54LJBz9p3TJCJJpsmZM5bXRhDm
         /njw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Hg3CZyEr;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id ce35-20020a056122412300b004937daab34esi638028vkb.4.2023.11.13.20.46.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:46:37 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-6b77ab73c6fso4033608b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:46:37 -0800 (PST)
X-Received: by 2002:a05:6a20:6a1c:b0:181:7d6d:c10b with SMTP id p28-20020a056a206a1c00b001817d6dc10bmr2434042pzk.7.1699937196532;
        Mon, 13 Nov 2023 20:46:36 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id hy13-20020a056a006a0d00b006c7ca969858sm398052pfb.82.2023.11.13.20.46.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:46:36 -0800 (PST)
Date: Mon, 13 Nov 2023 20:46:35 -0800
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
Subject: Re: [PATCH 17/20] mm/slab: move kmalloc() functions from
 slab_common.c to slub.c
Message-ID: <202311132046.04096EE39B@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-39-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-39-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Hg3CZyEr;       spf=pass
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

On Mon, Nov 13, 2023 at 08:13:58PM +0100, Vlastimil Babka wrote:
> This will eliminate a call between compilation units through
> __kmem_cache_alloc_node() and allow better inlining of the allocation
> fast path.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132046.04096EE39B%40keescook.
