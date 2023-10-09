Return-Path: <kasan-dev+bncBCCMH5WKTMGRBT4RR6UQMGQEMIANLTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B84D7BD719
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 11:33:04 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-1e583e9f7c0sf5238824fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 02:33:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696843983; cv=pass;
        d=google.com; s=arc-20160816;
        b=oUXXe5C9nbmIV67jlClvidLJRj824X7ISWKWbJU2Gylx1iOdtU0VQJbCFrLTyr2xiE
         Gl/h4o7sWUQRMXMctkYa5pzID3zm2cNfVFx7vRhfDQphPoqe65iy3M0htVOZCnT3HAA7
         3CrS5iGdYkbzX0/MxQCXr7dFeU2MgjZYPfK9mIFEBDmIdtzUbgOuqwRTBjYBjQNwiZ12
         LEop3eVHsKzUy8SK0sBSORaq1GHY0bWEETfQ4M93qWAQiApm36WrPGzAUKI9FfVUnuZA
         46AH3cxq26n0+LuSMnb3AY+PE/423KqJ1LHu92ypyJL46ZgDC4vf0YJ4QjNFG77eLvv3
         sf0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=47ZPIxbb43H7iUuwFEk/o+RFbE+N12WCxZiJ0e1tbLc=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=CKb4LJznCFyKUUDmPyPEWPVuc3tlFjw7VuGFq8kbgcGtOaEMU9RihlsmkeL8UoWR1H
         xSOg68oaXnkqWoEtDtrkkhVLsUA5hQE7Ek0yOoCPk0c/op/SpRWXJMvfEhHQ7sPUdyYt
         GZNT06mziX74hfAnPgurz/77SSpYZvXOrnqOwaGsAy0K7PaKq8cUjWzWADMdEzPM3Zo0
         02pyhaTf2E9Jx+MbQUOvE80ekH6MCCbt3dEW0objSVNWL9iLTZLTyfKiUB8n5wObK8VQ
         FKTxxWPeWw1S+g+UPSsC6tUF/uNKpeFlSNywsjYxEmC8gyOXkkChx3Wt4y9+EzwCQkpQ
         PvYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JrDMFazs;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696843983; x=1697448783; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=47ZPIxbb43H7iUuwFEk/o+RFbE+N12WCxZiJ0e1tbLc=;
        b=rVslAvbCPUKkXGQrL7mwwegQhGQ0bdbSMfL4cLzNiWv7lKTL0l1OuvzjLEKMKz6X74
         h8DDfaKJtgUWqsu3iSU0suhySp5KsIjehMwmtsSGcUapBllwJ6o+4Q3lAVuBwrYcj1nR
         IpvaHa6s5JDm8QOwKCio+ikzSX5mwX9dBkhga8jenQtUcTRw3x9N0GJkVkHgOOkNruLB
         KDq2UTBvOuo3e3fhzvhpCq7LNzmRjwUFP3N3S82APpEyFsx0z+mpsMUYW6YD7B3IkYEv
         zHvcyQQmDBv9FkbEOjQd11SQvJs4zinLqlB7aSysyzDrOGg+rgVTobWMpmaqYOyX3Q5Z
         teIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696843983; x=1697448783;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=47ZPIxbb43H7iUuwFEk/o+RFbE+N12WCxZiJ0e1tbLc=;
        b=CI6rGJHtTh1Pwy1tb7LCjX2HaUBDTI8/+FuZMPJUOIMr/xPsoVavLuWnCCYxcl+X4m
         QES3ef7rKFMu0LDYcAhQ8pn6EF6B1T7D5Os/SEiO44pS7Un/QL2xZDduV0ziwbjyIgcD
         qYKeGE4yMu2UXqiH0EI5NQDGNa1w1sUN4bPOne8V+KGnbcZlopWPS7A/wGvVNUUQgmVF
         rrbofCmOF4PTUPKFWjuYVMdBCE9mJHWpEjc++B3c6fe8ruxVY9ZeyL6bM4/uEzRFAi79
         PQlZgBX5afV38V+vuIgjM3ezgw2dLm4xpIWl30ZZ5twuGS4ED5wcW3w+VKpoc70gXfR3
         qpAA==
X-Gm-Message-State: AOJu0Yz1gPqRGy1iwVDqkuSGLu0tvqOkWwz8A4IAi4am3xHJI6LuXZDJ
	zWqKfbSr6NstZde6QHKrGyI=
X-Google-Smtp-Source: AGHT+IGVY6tWRpwoJENL7nMfhGsZWynCqG4FStoPXeAGJ6rk3e3J63zGXU6AVLyXxyQrkK445L9AQg==
X-Received: by 2002:a05:6871:70e:b0:1a6:b183:b0ab with SMTP id f14-20020a056871070e00b001a6b183b0abmr18581902oap.40.1696843983281;
        Mon, 09 Oct 2023 02:33:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:560a:b0:1dd:651a:720b with SMTP id
 m10-20020a056870560a00b001dd651a720bls4597104oao.1.-pod-prod-04-us; Mon, 09
 Oct 2023 02:33:02 -0700 (PDT)
X-Received: by 2002:a05:6870:160b:b0:1c0:d0e8:8ff9 with SMTP id b11-20020a056870160b00b001c0d0e88ff9mr16643843oae.16.1696843982531;
        Mon, 09 Oct 2023 02:33:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696843982; cv=none;
        d=google.com; s=arc-20160816;
        b=WwYM8bIozMIb6wWTJk1xQpIi0BsX+nPnnOEoMXzBKCPiIWv/xRMLTd9rcVFoEYwT03
         8Sn+MDeYp4QlO7N5hPkUjXRb7p/VvWeaoa5D+V16RDLoRp9LvPTVUzhWipvomQE9nBiL
         2MhxgrOxJmF07yN5tFcFal2t9fPrsfp83wVWnJyVdS3aUUyHUH+YuSCKfs2/nYLhr3H1
         DBwcfKI9uA3wH/Xq0mXvHl0TsXiNCcZCQcotsERoo6A8Qz17ag8BtcfbJG+3EuUg9H0W
         TTa/k3AMAhwkSnGAnUDNHrf9dUMK7JBI0Qv1YdOqQRsnwHxTP2hU+1eouSNTIT7eimRU
         /Z6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Fc2DaCMixY7eiqSJldB8Emg0r+LnGTFB1CXp+Shw46Y=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=Z363ocz+tYnNaTL7Z9YefOwu8IOmBruHVsgbRi0EqWdSPnXraqiIrNjBEoQ/9pOklS
         iJBY7JtZu9aLW8xGi0agNtqoggXrSXB5iUMQ+/LiN7BxmqGntkaSKbzJ262R1g+IC9y6
         52c9+GMKJ/7o/jkWJtcvgmAks7TmMhuqyL+rslOKdiw06ILLOpykbuw4/9AW60UoTV1Q
         qIa7RjPU/hzFBRVYjljh7SgZ8jPg8SOaLTAUJ4FH0kwwp4A8kZdCLphgBU2yGLDvTmQD
         DzZocbBsh7oK97Xa1dmzcf9ndI9cLr3X4yStBLRnocRmyKZXEFP9/L5fM3ayh6WknzKW
         wI3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JrDMFazs;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x736.google.com (mail-qk1-x736.google.com. [2607:f8b0:4864:20::736])
        by gmr-mx.google.com with ESMTPS id ti23-20020a056871891700b001d6741a71e5si657351oab.4.2023.10.09.02.33.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 02:33:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::736 as permitted sender) client-ip=2607:f8b0:4864:20::736;
Received: by mail-qk1-x736.google.com with SMTP id af79cd13be357-7741bffd123so318994085a.0
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 02:33:02 -0700 (PDT)
X-Received: by 2002:a0c:8f0a:0:b0:656:3352:832f with SMTP id
 z10-20020a0c8f0a000000b006563352832fmr14547557qvd.32.1696843981887; Mon, 09
 Oct 2023 02:33:01 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <b70a6d84c438ae20105ff608cd138aef5cf157e6.1694625260.git.andreyknvl@google.com>
In-Reply-To: <b70a6d84c438ae20105ff608cd138aef5cf157e6.1694625260.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Oct 2023 11:32:21 +0200
Message-ID: <CAG_fn=V13PRuq873BgkfP9oSd=_0VAeyxNJtbpZOzQvQNxCEQg@mail.gmail.com>
Subject: Re: [PATCH v2 10/19] lib/stackdepot: store free stack records in a freelist
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=JrDMFazs;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::736 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Sep 13, 2023 at 7:15=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Instead of using the global pool_offset variable to find a free slot
> when storing a new stack record, mainlain a freelist of free slots
> within the allocated stack pools.
>
> A global next_stack variable is used as the head of the freelist, and
> the next field in the stack_record struct is reused as freelist link
> (when the record is not in the freelist, this field is used as a link
> in the hash table).
>
> This is preparatory patch for implementing the eviction of stack records
> from the stack depot.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DV13PRuq873BgkfP9oSd%3D_0VAeyxNJtbpZOzQvQNxCEQg%40mail.gm=
ail.com.
