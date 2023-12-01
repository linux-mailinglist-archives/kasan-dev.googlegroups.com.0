Return-Path: <kasan-dev+bncBDAMN6NI5EERBVESU6VQMGQE3FN34MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 98599800A20
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Dec 2023 12:53:57 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-421a7c49567sf257991cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Dec 2023 03:53:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701431636; cv=pass;
        d=google.com; s=arc-20160816;
        b=IGwDgIGcucnGLEqjC82hbsR33eD/d5YM7sbEaMQZJyV4xxrKAuK29/kM6u1Q0y7btS
         xfOxeoU8pOiw3m1f5mVryAwaeOIHyvqXBSiDb919yx8LXUiVU++JGw7j9ebPG7D9MdZs
         PIwdL5fcHSnAvc4Ru2sPTqaShXhiZsou1GOO3lbutrwmRXas/9Zzft5NNaC8YNlTUwga
         Jik9PTx64vPy953BJku6eKyw69DdQHtXnv8nFn+nCyq65NJJ7kPq4iP1fZ5wlvBTQCUu
         /jkCbOVT4CA48hayYPROWHZHS5gMU/8FqT48XGdk8ytSe/TMMBpLX954oYXmUK+kdjqk
         Wz7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=H4mFCxNsKdFkN1XtYYjeZX7o3MdOdsMGSygo18iaHjM=;
        fh=K4DIRFCyG3pvbBjBFZQn+gNijzzaXH+Ym9hZb4wug5Q=;
        b=08aUrd5yXJDnQZpl8ZMU5qwK3lNC94nduspihZ3eodHbVx91nH6LAzfH8Rekze3pTg
         zD+xMZOWVg0ZoJSj0WvChO5GEeUrhIMf+wc/Ok+JJ4WbUJ0M8LHnChZqTbdvGf/v+iSe
         iL/WvG/gH1oS+JZzKrp+F7x1xX5Z2ISSkLktFnDsHlBDyHxUawpcx8NvL9Us+OmEFxRU
         9Umi/wztSAbmM0BK/tvWwjM3TW4Z3Kt4TI6+ndRr7knkjgBXme8c7V2/ADND8GQBut85
         H8VuuFVxZZtEZzQWA/Ntz7A281qBUw0aeWizr5YUMpeveaWOzR2MsBNIAjuc7smt8Qyb
         bcUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=AtU97WuW;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701431636; x=1702036436; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=H4mFCxNsKdFkN1XtYYjeZX7o3MdOdsMGSygo18iaHjM=;
        b=ph6NvvRSMEr+N+B3uCzn/tr0sGWpz/1jKRIrH5r0B0tsF3rYQkg5bnL3LfIGO9YJn8
         iesrg0lpaFFTQ/bkbZbyXMLmFkcyJAZv66iXenY6GaJFAJM5t6fHBy+GwmpTAS9CVvpg
         cmHhsgdKOvNhOfKoLSOfpo/lsizXUJqpoebWE9PU0neMte0v/1rktIsBwvZiCi/g515N
         /oYnkv8A4dGAWffBhs/ho69iNkdq26MHc79NJqqO9GhpmrMC8WYkE8rQWQiDTTA21PqX
         xuwg0dNgI1WkR6OlZ7Q0sIbLYa+QKm1QKAttogEkfJk7lCyUmUjXle41G0IZDaWSv0L/
         pf2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701431636; x=1702036436;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=H4mFCxNsKdFkN1XtYYjeZX7o3MdOdsMGSygo18iaHjM=;
        b=hpDWUdlum4vV3iODwKcbDs8wcCTEGNHwnG4V47n3IGn75CzbNZHJCwJrJWadOvYloX
         PGClLMViyifME8s8PwtQdj5XQvQFgNy6TeOTdEjmv0YoRQX6jCuFbvRqtFjKHHLVVS7z
         UZtxZ6N3xh7ary8nR4vO4Zxjh2tns5FNLpbJsQjoqv9xNM7qDQzM+1kN1RPSyqJ+2D9Q
         ewkwYFYhnVsSMLPQlERO4XjzEsbH2DTimx1s6J4e7zw3r05+pTpQCnK9Q2jZdCGtQZ/Z
         cFmRrM72BaFZ+HjEAMN/uE2crsR3m0vS4qQQgXfCZi+mYZsxTovEiJcJleQnHnr5/g6K
         9EyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz6mb8f41WC3/FBDgS3vmQfvIEKNprg8SMxlXyUlo2DLw5JmWGr
	AsjlaKEXDiolt2uNo81lJAw=
X-Google-Smtp-Source: AGHT+IFB+mg4ztwKx6YF9uRQghKgpApYwL/QIDYdBcsnQNUTEbVOdic3ouMq5XaKRXEEu3aYEm7R4Q==
X-Received: by 2002:ac8:5a8d:0:b0:422:1bd:470a with SMTP id c13-20020ac85a8d000000b0042201bd470amr169424qtc.24.1701431636313;
        Fri, 01 Dec 2023 03:53:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1907:b0:423:7c51:c729 with SMTP id
 w7-20020a05622a190700b004237c51c729ls14405qtc.2.-pod-prod-06-us; Fri, 01 Dec
 2023 03:53:56 -0800 (PST)
X-Received: by 2002:a05:620a:2182:b0:77d:ce56:e9de with SMTP id g2-20020a05620a218200b0077dce56e9demr233421qka.1.1701431635862;
        Fri, 01 Dec 2023 03:53:55 -0800 (PST)
Received: by 2002:a05:620a:2901:b0:778:a9dc:3cb2 with SMTP id af79cd13be357-77de1aa9737ms85a;
        Fri, 1 Dec 2023 03:28:45 -0800 (PST)
X-Received: by 2002:a05:6122:3106:b0:4ac:22c7:89d5 with SMTP id cg6-20020a056122310600b004ac22c789d5mr21376191vkb.2.1701430125221;
        Fri, 01 Dec 2023 03:28:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701430125; cv=none;
        d=google.com; s=arc-20160816;
        b=OZN0onDNBEpppmYltOp3J8pGrV8EqdpVAyt3cleNOxkE7huHvC1lexnsq5auqCwv1U
         FSXA4YxfkvsnILzeP6EBkoO6iQ/bD6G1Vne4xmkaAwvbJSJ84YjtYTlRcorhMYWYfBkT
         ZPbpmagItep5gFIdCUjjDzz1ul1LtT5uo93PpSbwiTk/PTBN5PAfyA/Mo1ZzyfPW8ch3
         /w9rz7H0OQyKYg+KgrRw43zRRNcL9sMh2gw5c8S6GqjwY7KqHMwO3eg94OjY7kc1nbmj
         /4L2QVAJ2aRlY1vdS1oEPsDcleLdX/zz2cR4G36LmsbNagRepqL+KOjFifEpIA7MUGTO
         IvjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=kxBXQG/f8kU5v0EK+ncURnwi12nHyxr77nDpaGQa42Y=;
        fh=K4DIRFCyG3pvbBjBFZQn+gNijzzaXH+Ym9hZb4wug5Q=;
        b=uULDcrQvwKQWg5yVN7MNUPjSoioJdZb4iCJVsHqL3dLT/H92TFiOQG7PFdRXpNf+cb
         u/Hr+twxPunL/cJ+T+5H5Mr3MFad6xQxk7aCt1DojZ3R7kLYkHv+GorxRs/FvwWVzHK8
         +5GHbPpMFOC0JxVF7K9jWYeJTGnWvCCvTNQSdpo7m8qqw3K7GBLohih6EH8lSBD7sjEF
         nW+2hYljAZyuZLUAVNyYS+y9RKwD+ec5T9KrNjA7RRhwN7FyiVfBwW/kE7tp64GBsV9+
         qyGunAhYl4HsO+JuazyPGvI5Gwn4bneGLKoKSJKAG9ukcocGbwnr+4IGi9OvmRi/kwWR
         O+NA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=AtU97WuW;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id l73-20020a1ffe4c000000b0049d13f0321fsi498147vki.0.2023.12.01.03.28.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Dec 2023 03:28:45 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Vlastimil Babka <vbabka@suse.cz>, David Rientjes <rientjes@google.com>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Hyeonggon Yoo
 <42.hyeyoo@gmail.com>, Roman Gushchin <roman.gushchin@linux.dev>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino
 <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, Johannes
 Weiner <hannes@cmpxchg.org>, Michal Hocko <mhocko@kernel.org>, Shakeel
 Butt <shakeelb@google.com>, Muchun Song <muchun.song@linux.dev>, Kees Cook
 <keescook@chromium.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
 linux-hardening@vger.kernel.org, Vlastimil Babka <vbabka@suse.cz>
Subject: Re: [PATCH v2 06/21] cpu/hotplug: remove CPUHP_SLAB_PREPARE hooks
In-Reply-To: <20231120-slab-remove-slab-v2-6-9c9c70177183@suse.cz>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-6-9c9c70177183@suse.cz>
Date: Fri, 01 Dec 2023 12:28:42 +0100
Message-ID: <87msuuxitx.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=AtU97WuW;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted
 sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Mon, Nov 20 2023 at 19:34, Vlastimil Babka wrote:

> The CPUHP_SLAB_PREPARE hooks are only used by SLAB which is removed.
> SLUB defines them as NULL, so we can remove those altogether.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Acked-by: Thomas Gleixner <tglx@linutronix.de>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87msuuxitx.ffs%40tglx.
