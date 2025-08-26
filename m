Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFVIW3CQMGQEFVW2JYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 89B12B35A8D
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 13:01:44 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-325e31cece1sf2069327a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 04:01:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756206103; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZfmcPIfc+aQd0owY/hKhM+uaPHgvh7Bg2/zaKzDXb6kFuLlywzywALqTL8gsA29lcE
         BO4FoYqh3M+CLIWEEShGrvsumoNABNpxyhy4fs3McUoCxTWsnsMT+M2ksB2ejwyUmPPM
         szHIyOGq3H7//dcR5nW5MswU7VoV6kXfJp/MUzIi7BzS8h3vfixnCpKp5XxCgLrhlvFx
         SpM3XHapxHk+fRc15ii0I7J1z9IuAZpvrMnWqMM/fhcGG5nXp3Fls5ZibFEnpUKDsqkt
         0WdDzKtRn0xiGDrjuY7KsX/Dn7P8nrHrIMUccUFprTQqO3JOH2K43qXtouwBXiZpjVKG
         KWjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lQ1tQBG91Ygv/twURLKv9p5p9JKcHBEhBOzPX5gUVsA=;
        fh=cRe3ufHGzf4kHi014xbEuNy5MMOa/KJyhaShcC6nyKY=;
        b=C17MXgB4tEx2UTM+El/Z+VvmEGEEsHrD0kErH7CQIXSv3KzG5TFtfyLRFQ+AqoRF4r
         dMIIrRrL5J20npXyF3pf5uZQxxQV9qOSkoDKpXB1bOOHQC7XM2EYbnZ7N9XeD47JG1RM
         wXY+gg5mg2i6oRYF6JcvmlvyYb0Kl8QMRN2MPfr9ABZbvIBbV3rbU0TTfMPvN0LYYMf5
         zWQ8xhms/LnG0eEJ3WpJCnWal8iujfcxGk5ZRRii7lBpN3cpkxkDzRqbL5z7EridFqHt
         1PSh1fumnvSSUI9k61KLPQPBYg9Ht/34kP4q/+HrH7CaORDoVz/EfA/pLgy8ttgulIHE
         OCSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zQLn5a8I;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756206103; x=1756810903; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lQ1tQBG91Ygv/twURLKv9p5p9JKcHBEhBOzPX5gUVsA=;
        b=gTslqgwahSksSwnB2feidMEr0ct0QXkDgKVTE9yHiylAnI7S8lHdqdK6+l3xQcgXkH
         rj9rrIEa4rb3Irg6C8+fRrvk2zPchVqK4bJX0RN5wwhHC4Maq6TyI2oZZP3GWK7+6Thj
         dhE2Gc7vvOGcgp2dxreUyWaMh4iFrMJlKhdpBoaBYBrG8s5BrmrUKb9n5TzKAQrO2Tkr
         QujkYYRu+VX9JNUAI4TSvoSCyBRMT3E/dOi/WJzyeIvzEPPrbl6CJFa5jgiJ2F/RCQzu
         7Uhu87stihdwTxAP2t+S25J7fgNwJlbXAZsePocJKx4pB45OK4+eeXQUHvRqqIg+uP2P
         IiMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756206103; x=1756810903;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lQ1tQBG91Ygv/twURLKv9p5p9JKcHBEhBOzPX5gUVsA=;
        b=YTmOGDtXQewWvH9M1EdKbuhlOYI/yLXXqZpPuWEMIOLW2as1zrkZ9eputJCAI07yHq
         9ctoFl0/UcncOZcoD0BFpQx4YOGjU3p5uT+LheKQvzUGhBaqIDfG3+c31AHekIv1yZEA
         QHkYGFkx5UUh6i6a0aCt9ILBt4LGwU4tdLqyp08RYSQOL1Gsx5Ss7lxPfQRHApoIpPjf
         BjTvfyVXePziBj/W67oapdth4bH07q/Ngn0Hm+hGAd39IBo7gjQuXsYpaPjT8TWyqRO3
         MeB+ssBjEhzE1RQHnCcwFvGMkOofznqjBaw3EEqGCkLm/uYYYkQ8xE1PVn9MxjlUygyw
         h3NA==
X-Forwarded-Encrypted: i=2; AJvYcCWzg3TwQ7gzT1F3xdv0WQi0oehagA/Pwubf/LebGvvPBnYC4g/KcYTLvVBxOAX9y/2Y+cDPGw==@lfdr.de
X-Gm-Message-State: AOJu0YzPdXT7RRmsCriBi7Mh80OvScma0WU+dVXSD3svvOK4b1xhhFk2
	QS4/pbk5XcomBGGkeS+7HQD5YRCQbFbStorG5jWUFPIN7QFvEetwawI1
X-Google-Smtp-Source: AGHT+IE3JycMmyxAqzt9h6qlodmkjh4dX2PcQvDU10pyXwS+yJ4BreRPyQz7Fg2xQXbtLl1Ri8XLCg==
X-Received: by 2002:a17:90b:5241:b0:325:4751:3446 with SMTP id 98e67ed59e1d1-3254751346emr17496419a91.24.1756206102863;
        Tue, 26 Aug 2025 04:01:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdgKlHnd4Wx8pfS1I5em8u48pXK8ErWj+SsOXdAE9ZLdA==
Received: by 2002:a17:90b:4a47:b0:325:9869:709f with SMTP id
 98e67ed59e1d1-32598697228ls2271656a91.0.-pod-prod-08-us; Tue, 26 Aug 2025
 04:01:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXixROp7Wzl8xswAQGufHbIOYu4b+UzazUr2xxXMYc8ujLpjMRumN2r0w6CEq7sjnjbYEPCHxyH6kk=@googlegroups.com
X-Received: by 2002:a17:90b:2e4d:b0:31e:b77c:1f09 with SMTP id 98e67ed59e1d1-3251774b61dmr21158359a91.19.1756206101292;
        Tue, 26 Aug 2025 04:01:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756206101; cv=none;
        d=google.com; s=arc-20240605;
        b=dXoyroTmH2WKWKvFNW+QQUKxdvm9TLyryg5zB2thL0nGEdMf3CB0uLDv0kz/R6CO7E
         Ce6b5GnHGvJ+llb4V8taSZ+8hxu73vXyN3DoyT2hgMmcCabEd80b8LZwj9uY7+Umshpe
         aChUaVycLOpT0liIah3uqwk0wwxakbVuTFajreskn9IqWavQk/T/E9w9HRpkX7Nlmbug
         o2tGXWx9sg9e/yvXBMfuk8iJh2MphKJm3L5iBIEmeXGchQAPm37ZRDpDrTfWcXeFYQ+q
         oIKeSAJ8Y+X6F174iQoErcaTLWYbzokIGVbQT+aVJ4Ltf0g4xx3eDCEc7izemM59xcD4
         SerQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=O7NeKTyWKueL+wvA2d/ehbUAGIe9IQuhF4UrqPvxaVg=;
        fh=U8cpi6gZiJMjXIfLhsbGeNzygcVzk5CNuC0l5mU7thA=;
        b=SgiVREUuI5XqyrQB6cwv0TNKlTOSh6C+Q8+XwRSpjRQdnJnlbxb6PZW2K73AY+YHnz
         e9tM7zwx5KYQitaZxRShS0UHrqInuES0AvEh7xrssYAJ0jM3uYvp9ijM/ARIpGvJSZQ1
         kUq8oGZfIDjASCyj4UfjOhA+wLqZvVoClLOYs3rFsjP73hwU8qtpMZD/R4PL2PuJd6uf
         ycpB6JsDc0Ki2nsrtwRqaVHmNX1Nrl2Yy8KwRW/eyCqa0FAPGLMEuDZIG4SxTgnoDRKE
         qg5UhgrhW3s83GBG6MgbL+TQBQirtRbbvtqN1F14A67YaoUR7XRyWIjy9k8Z2b5/o2/N
         OOkg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zQLn5a8I;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32745723002si54755a91.1.2025.08.26.04.01.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 04:01:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-24884d9e54bso391235ad.0
        for <kasan-dev@googlegroups.com>; Tue, 26 Aug 2025 04:01:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVgVnOjQUQ0S/ox0QTF9szYU7qc5sgwup9MBpwa/CNNoPYuXY81f4wUV1IuQJD0Ry48vP54HGueoE4=@googlegroups.com
X-Gm-Gg: ASbGncu4tM1CgZWbGEQCOLRGz+IgWCcz71eCKGh+OSlPyhHkKJ+w6IzLChBmFlQU2dV
	BUIDicEzgOnXQwU79F6B3LL92MUgWngZfDN1nXJmtdeT6Jbm5NtXx1O6mOCFOcsMG+NQslDdJmh
	Bz32/CRR98/u+8Y/etERIYCueEQjsH+kvzlgyVHxDpWOjEqvtj+b0ox+7H8tL91cIolddQNMIkc
	kBEsp6KqjpGRSe8
X-Received: by 2002:a17:903:240c:b0:246:cb50:f42f with SMTP id
 d9443c01a7336-246cb50fe74mr114988865ad.19.1756206100525; Tue, 26 Aug 2025
 04:01:40 -0700 (PDT)
MIME-Version: 1.0
References: <20250825154505.1558444-1-elver@google.com> <97dca868-dc8a-422a-aa47-ce2bb739e640@huawei.com>
In-Reply-To: <97dca868-dc8a-422a-aa47-ce2bb739e640@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Aug 2025 13:01:03 +0200
X-Gm-Features: Ac12FXxae71NaV6L-XhwcBeMdDL6EXr8UiNrPYGSHEYHL3QrAfVUO23SnPsEAGQ
Message-ID: <CANpmjNMkU1gaKEa_QAb0Zc+h3P=Yviwr7j0vSuZgv8NHfDbw_A@mail.gmail.com>
Subject: Re: [PATCH RFC] slab: support for compiler-assisted type-based slab
 cache partitioning
To: GONG Ruiqi <gongruiqi1@huawei.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, David Hildenbrand <david@redhat.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Florent Revest <revest@google.com>, Harry Yoo <harry.yoo@oracle.com>, Jann Horn <jannh@google.com>, 
	Kees Cook <kees@kernel.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, 
	Matteo Rizzo <matteorizzo@google.com>, Michal Hocko <mhocko@suse.com>, 
	Mike Rapoport <rppt@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Suren Baghdasaryan <surenb@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, linux-hardening@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=zQLn5a8I;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::633 as
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

On Tue, 26 Aug 2025 at 06:59, GONG Ruiqi <gongruiqi1@huawei.com> wrote:
> On 8/25/2025 11:44 PM, Marco Elver wrote:
> > ...
> >
> > Introduce a new mode, TYPED_KMALLOC_CACHES, which leverages Clang's
> > "allocation tokens" via __builtin_alloc_token_infer [1].
> >
> > This mechanism allows the compiler to pass a token ID derived from the
> > allocation's type to the allocator. The compiler performs best-effort
> > type inference, and recognizes idioms such as kmalloc(sizeof(T), ...).
> > Unlike RANDOM_KMALLOC_CACHES, this mode deterministically assigns a slab
> > cache to an allocation of type T, regardless of allocation site.
> >
> > Clang's default token ID calculation is described as [1]:
> >
> >    TypeHashPointerSplit: This mode assigns a token ID based on the hash
> >    of the allocated type's name, where the top half ID-space is reserved
> >    for types that contain pointers and the bottom half for types that do
> >    not contain pointers.
>
> Is a type's token id always the same across different builds? Or somehow
> predictable? If so, the attacker could probably find out all types that
> end up with the same id, and use some of them to exploit the buggy one.

Yes, it's meant to be deterministic and predictable. I guess this is
the same question regarding randomness, for which it's unclear if it
strengthens or weakens the mitigation. As I wrote elsewhere:

> Irrespective of the top/bottom split, one of the key properties to
> retain is that allocations of type T are predictably assigned a slab
> cache. This means that even if a pointer-containing object of type T
> is vulnerable, yet the pointer within T is useless for exploitation,
> the difficulty of getting to a sensitive object S is still increased
> by the fact that S is unlikely to be co-located. If we were to
> introduce more randomness, we increase the probability that S will be
> co-located with T, which is counter-intuitive to me.

I think we can reason either way, and I grant you this is rather ambiguous.

But the definitive point that was made to me from various security
researchers that inspired this technique is that the most useful thing
we can do is separate pointer-containing objects from
non-pointer-containing objects (in absence of slab per type, which is
likely too costly in the common case).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMkU1gaKEa_QAb0Zc%2Bh3P%3DYviwr7j0vSuZgv8NHfDbw_A%40mail.gmail.com.
