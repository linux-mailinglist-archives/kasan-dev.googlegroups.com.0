Return-Path: <kasan-dev+bncBDW2JDUY5AORBIWM3CTQMGQEDYJKRIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C0E3E791D5E
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Sep 2023 20:46:59 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-1cca78b59a6sf1789938fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Sep 2023 11:46:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693853218; cv=pass;
        d=google.com; s=arc-20160816;
        b=jSH+fz3wVIKK4DoGGAyIbUVSclYBohDVeBKChRPkXceDp84rtHApwzN3MIXmgzOEEv
         BAGrW2eKP5cSrjDqtXbswSSMGYuC06xS9o5EsLkvhvCMIHkNjLI8nbfKbYeX/c/eDLEQ
         zC81Z11+FVDFNGNI+0r1Y4hlGozyp1PjkUXvC8h2vJ8xRBRCyDW74h0a1h00YIsDvcar
         QryLfw14W9jAklWnnk3KhR0Qn5jugTqwNs3Rj/KfGlDj7qoDN6PmGsXqoZVkH3kYDSNx
         nQCPIPXC2l1FYdGe+MoUHz3y3nlRng7egL0At8m8mMvuIKMwOj/EAWPS8knMYh+4ceVT
         UmnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=RsLYShxnFjWgVqjKgabYEdFH6/bpIjA1fKAKNbtu+w8=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=D5Zxc22sAFzxO6jJIrMI+p53WVwc4PgbqBcdYELCMGqXbH8+aVaqPaXXoX6zKCvpn5
         /Nxb8/i9xTjrskCJkjQlNunKy0mxczM/pdSNN/5Nwfzrhc4O9g7pp1qhddIeG2UKmpjw
         tcT5Smcj6TasCjtR2z9oGTSIHoA2uXwdsM8AgQIGEtpnI/zCgRZhM8OmvneOymilBmBW
         /eGkgfOh/QTccuwSgZ3PvhtwdZ0W18wB3gGGEedZ8F6pYEh1kjSILsrDC+Gfs63ibMGY
         OqwAoBCadEw5nn1sjNfy/RZWOVOC0TFrp5HGOlQrhc89UlBjFlKDDfPY0dEdrt4GO2hP
         E1nw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=A+xDg1Hu;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693853218; x=1694458018; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RsLYShxnFjWgVqjKgabYEdFH6/bpIjA1fKAKNbtu+w8=;
        b=l+I9Z0n4f9lfIvR72GSDtng4caElqt8i3Uh0N+ABWghd5gbdBR50YU6v7e4WExiO6W
         GbsZhBR1N3UBBtnao7twngjklos81/ZL0yXhut9vzd2s9sIec2tEOBtiI/UiIq7JI/km
         lWKDm3tg3uxQfJrFf0cbLn5UvTE94uza47pqnooajKs8FtdXExkFkr437PIPwgmhWvop
         oIVExjRCqF0x2W87lN41onzYBLSCF2emwKNpE8EDi8bH/N2dykmC0lX/EMVFSi66J1rh
         3kztlLi5Uo0mYmHC32JOWX8dw+AO4kPUS6wLHBWjyZhupDnwgan8zEJm5RraL58lVNdC
         Gsow==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1693853218; x=1694458018; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RsLYShxnFjWgVqjKgabYEdFH6/bpIjA1fKAKNbtu+w8=;
        b=Hcz2OdjFyxvRV85bx0C57hivSeYUP/73iG5+8+YBTa3znNocn6zwghbnP73B81zS6x
         73IQIvHj1AsC8d4rZq/Xue2hP3yZH6eZzUhuDUL4Zbh1oKBIHamEwxlqU+1l9KQNC5/B
         DCt7/2Y84yh0dPlmycdyJL2/XdWlCcG0wM5fyfGksLM6UId/IztDaAqM6/ZiJe4UOF7y
         +MGBkD4nBXGW1S7/GCqEYoRtAd+W1IRlI5SEEs3DKfSDcDrOXfymgOX68PzxLGhQf5SF
         qL+QxJhLnexjWJPWBTYxJyfp1Pgh4o3N1TJUmeF/CHvfrPs/ubAkK98OiZXX2kGgPUcl
         62kQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693853218; x=1694458018;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RsLYShxnFjWgVqjKgabYEdFH6/bpIjA1fKAKNbtu+w8=;
        b=fpoSqGoy7Wq1ATzcGDvFlOd3vTnxZzPXYg+R7jMZAOjCPqK8AMvFze+tvJ/5LmrJjX
         3oQ3IO/9vjO30PSb0OwsOsHnWMdJVUB8ZDcXJNZZFbSgB2s59fHFjp183o5i/DypJiKd
         sgiKDn3DB7KgDohYiz4P0WffNuei9WQ8mEldOWsXUlrqMHwBuliJ7ZDukVcA8XJaMkLZ
         twfKPB64WJh2A1Y4vcf27QBXWNQF7HgydVu0ctIgPjTVo+c+uf2T/DtDNk82jeYApPAq
         HDAMYsx2ZY9jGJu+xrTa7CCFWz9gJjtkYUVKS7wXiSW2kBz8Jt+UO1/azofz36j9ESEN
         xfog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzA8snlUnWFxTX9Imd0Ja8psM9OPtlpjJ083AjtUX6WbP6s2ArC
	kk8QHB+QnvejfvAN1OCByLw=
X-Google-Smtp-Source: AGHT+IE2T0hTomQ1WTb9r0Xhlz3KBB4PJSICeCEwSpqOqEESQ7YsfN5KpQttu3r0t4nkHIloO1i7Cg==
X-Received: by 2002:a05:6870:d698:b0:1bf:1a58:c50 with SMTP id z24-20020a056870d69800b001bf1a580c50mr14057003oap.9.1693853218415;
        Mon, 04 Sep 2023 11:46:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:40c8:b0:1ba:7f7e:2b78 with SMTP id
 l8-20020a05687040c800b001ba7f7e2b78ls682102oal.2.-pod-prod-09-us; Mon, 04 Sep
 2023 11:46:57 -0700 (PDT)
X-Received: by 2002:a05:6808:f91:b0:3a6:febf:e1 with SMTP id o17-20020a0568080f9100b003a6febf00e1mr13810864oiw.55.1693853217745;
        Mon, 04 Sep 2023 11:46:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693853217; cv=none;
        d=google.com; s=arc-20160816;
        b=mUWA3KNlfEvEeTBSvLPzYk/BkivaSn7lpa+QnKzRanXHCESyJ/yQVVBC+R7I/sK/vj
         VlTdJHd4cx36vj5UbH8r3YMsrOyJdrok5A9ZGu/KOXdN7Fz+0C8JDfCic8PE2IViXxyk
         4HNxbzSzEl/a42Eb9AgldusfF0CgCla5IgObM7uPVHK8Bn4rYkPntTP6DHiYpOcKtVv8
         xdqNB7tWgliLY61hiFOdAFnNy4f7T5jeNnNTeZoSAOTbXg+GVPB6Wsrb2ekPbSQjPdF5
         zbYauPXKERUA3XbO/2dJSM9HkqX+a/S4oBAuIOTl0sr0H/fWMdZrfBNlAuB6wdznAWdi
         /KIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Y1p+GT6ZMy0ZqRPEzPWHIRn3xw5vD8ZF+TmPxh+UO9g=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=X+CKvZQKnJWria+pT7uqeXAYOh2pJXZUNewFk05dNk5+DLlqqeVj7rkfi+6UJFebYF
         Nk+VbDHEF1JQHNKBM5EP4pRN4YKshiXL52fAy6p6YkuXgp+TiCeFZj+T+bIOv/EjhSFg
         U2qT4Caou3XbZVUbj8TZyiDdiah96M5Eg5t2tl8qQSllRDa9vrBNL0Im2pd14LknEXe9
         nQyJTflzgBDlspSW09269sC21BCN5W3ZfKyY8Ig2yGHhhxzRh477JPDdJUgPYNAWmyPI
         pbZd32TEtFvIW/3eCURsmEwVZFGEph2JQWwZUlbNf7tSA8Txz0KgKOjj4ZNYonKsBwJi
         WWQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=A+xDg1Hu;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ot1-x331.google.com (mail-ot1-x331.google.com. [2607:f8b0:4864:20::331])
        by gmr-mx.google.com with ESMTPS id gt7-20020a0568082e8700b003a85eb09ec3si1760826oib.1.2023.09.04.11.46.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Sep 2023 11:46:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::331 as permitted sender) client-ip=2607:f8b0:4864:20::331;
Received: by mail-ot1-x331.google.com with SMTP id 46e09a7af769-6befdad890eso1456938a34.3
        for <kasan-dev@googlegroups.com>; Mon, 04 Sep 2023 11:46:57 -0700 (PDT)
X-Received: by 2002:a05:6830:12d8:b0:6bc:b80c:bd53 with SMTP id
 a24-20020a05683012d800b006bcb80cbd53mr10953722otq.38.1693853217401; Mon, 04
 Sep 2023 11:46:57 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <306aeddcd3c01f432d308043c382669e5f63b395.1693328501.git.andreyknvl@google.com>
 <ZO8MxUqcL1dnykcl@elver.google.com>
In-Reply-To: <ZO8MxUqcL1dnykcl@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 4 Sep 2023 20:46:46 +0200
Message-ID: <CA+fCnZe2ZRQe+xt9A7suXrYW8Sb7WGD+oJJVWz6Co-KGYghZLw@mail.gmail.com>
Subject: Re: [PATCH 12/15] stackdepot: add refcount for records
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=A+xDg1Hu;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::331
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Wed, Aug 30, 2023 at 11:33=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> If someone doesn't use stack_depot_evict(), and the refcount eventually
> overflows, it'll do a WARN (per refcount_warn_saturate()).
>
> I think the interface needs to be different:
>
>         stack_depot_get(): increments refcount (could be inline if just
>         wrapper around refcount_inc())
>
>         stack_depot_put(): what stack_depot_evict() currently does
>
> Then it's clear that if someone uses either stack_depot_get() or _put()
> that these need to be balanced. Not using either will result in the old
> behaviour of never evicting an entry.

So you mean the exported interface needs to be different? And the
users will need to call both stack_depot_save+stack_depot_get for
saving? Hm, this seems odd.

WDYT about adding a new flavor of stack_depot_save called
stack_depot_save_get that would increment the refcount? And renaming
stack_depot_evict to stack_depot_put.

I'm not sure though if the overflow is actually an issue. Hitting that
would require calling stack_depot_save INT_MAX times.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZe2ZRQe%2Bxt9A7suXrYW8Sb7WGD%2BoJJVWz6Co-KGYghZLw%40mail.=
gmail.com.
