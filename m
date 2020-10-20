Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCNVXP6AKGQENJ536FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DCC7293BE8
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Oct 2020 14:39:38 +0200 (CEST)
Received: by mail-vk1-xa3c.google.com with SMTP id b14sf438434vka.21
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Oct 2020 05:39:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603197577; cv=pass;
        d=google.com; s=arc-20160816;
        b=v85O0pDMLWFAIsJmJ1TJiztbwrSVbwt3D4hxNwPh/M7dbQKKf3C6/aSkT/npYBAeYt
         5bc6Z0NsBGZsxp+HZprPawn0B4vv+Bq9gs9UVr8rqMdRfTElN6F0peGsZVALILX/yQu9
         5tT1qexkjZQ6yLuffo7DIFvPwxPX3MI9XSZBhCPZ1oTCQHpF/wjmX1WjfJRBBp+DFtK/
         uu6QNSOq2nsqg1w9MF9bqY/pTLUAhm4mpeXu0QS5MM0Q6LLB6ciVSJ2rvkZLx+N32TxS
         51v3pEBSbU48tUhIZ8ZQYj4lIM2y2HS3b892DVKzS523idZ0R0dStIRsy5jzzxoh6d5N
         O+9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=W3JilW13grAHusEs55Ixv1if4i16oup5xLnT70QAQZA=;
        b=0mzivp/8GIKI+I4gzBanXDVTyGGbRbJwsOJA1Nv8egawA3f9X09HshrogHm99uT+Jm
         gffXGXQgquGsARNhvc1kKgCSMZdGCpwvxJ8Zx6XLyUETz7SR/n+fyqijXkaIZNS3FIAA
         K5Ijpq8G66bDs2tYlEM9tqmBghYoGfNKSErlMsM1x2lqYq2KMSkTBH5na3ij7rB3VqnG
         GI4jZrAQs3VyX2FM8KYYveBKkjKrDI4wUBZd7qs9fk0R1LM7wtWAvYNUPg3BLxcMFDiW
         z/4Tyshbg0QyDT6eaHdNnMGGYRjjGX5xT4NBdNm3KcxqUBWXaizP5kVJpvqwhvZeH5yf
         ar3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DY6DgfCc;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W3JilW13grAHusEs55Ixv1if4i16oup5xLnT70QAQZA=;
        b=mOqZAFVwpnH3X1O9vel6i86qaw2p1216kd9kOqpB0v5mElAfbNfiLmm0N56xdnh09F
         KWZpB4QQi0J1xCyDp5JYbW6ZkaOCyD7LGcmre45vRPxRxzaXRHUQGspMsPt6gYuSHw+f
         1jCGznmoYf4UJJcID3nCCQDt+CZl7MQeiFLvVN2MhKz7hQ6DVTu1/Bs1ksphPpHBs2be
         +312xLCuZS9OwQn3usF0zVOEekJ6J389FS81XVR1pa49uWvACWu7W5xv6Ify2WqY5GvP
         bU8MIuVLl1y75MMDkQGAp2sAVS8fq5w7iNJoVcsOsTaGrbPNBK9dd4IO9IZ3YHax1Oz8
         0Qzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W3JilW13grAHusEs55Ixv1if4i16oup5xLnT70QAQZA=;
        b=lSHQlSbZMe/npQuUTJQNivQ7rYtnWtU+/u6bILk1g68qMMYnhzZ2m2Pyc6bMphkYZd
         tr4zj8VzfIj2YWNYANT+4f4SwQVSvH5PwpQMpXHnIwF6WHftWF2ePiDPrf5QUfNJZkRq
         ROuOmep5KtfsKG9cJOO6qK8j3Op8QJDvslRbtjtUd0Ze6bnWa4l7b6eEZ9MOFLH7Wn59
         xMbOCt+IjCATxNdu5vnaldoLN/9yA8f2WHNR/7MS6K6S53z2JNEj8MAR0pJ2N1xXhXBE
         xxMxhQ13tEDNyI8HIqKZ8GGHAqjtAUjZbWGEqOP3njGp6JXvNU6HF8p39UH39ubW5xyW
         u37w==
X-Gm-Message-State: AOAM530v8YVERJ+MosEmRxeAsGBEU57a/OAvvK14gv2SmL5tb8W00Nfr
	XYxP7+gzUMHD3yw3e5n2Wt8=
X-Google-Smtp-Source: ABdhPJwdb5EbeND4vmMJ3oEvboD2o4xVQHi4QW+/K9Rdrf7lOrYRluCLB0VaFo/oE5LjL4oofzedKw==
X-Received: by 2002:a1f:6241:: with SMTP id w62mr1245733vkb.23.1603197577509;
        Tue, 20 Oct 2020 05:39:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9e47:: with SMTP id h68ls75623vke.7.gmail; Tue, 20 Oct
 2020 05:39:37 -0700 (PDT)
X-Received: by 2002:a1f:ad11:: with SMTP id w17mr1297061vke.0.1603197577022;
        Tue, 20 Oct 2020 05:39:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603197577; cv=none;
        d=google.com; s=arc-20160816;
        b=cASH/5swq6cvfgjhrX27EsoWtxrR9o2Bk4E1umFcYzGluJVqUW+J518+uD6IGOQTZ5
         zn90uaxNnFmhCeBBZ5LGMl2zw9ik05u2uZtNNB9k8JaCfoxQoGiZkHhu8D7n955PkIkp
         /6ik28Yc3YWzpshua79v+3ltsLjuntZCHm6VWq4D1Bx/cE62mRlWON4xO1zN1wOc4hW0
         0wKqedDSLmpG8UMj1mp7Ha6ng8OG3Ftjrl8sWyFJw71lXAQftzSvcPOKXagCqk7zpQ5e
         3tGWkGfFridS3c3X0/qY9uL/TgjZOg8J5ilrxCkBtwmRqK1mD6HWVJm+FYH8y7e8/93y
         7uSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LnygfgLF8jMqb/pqWEkYkyd5vX4PuOJ5AsXjq1S0C3k=;
        b=Cd+R+V1WMPD/9jciR+ppF1soEiQ2GGSQ7AGEkTHkXoEpDm3r8OU/3gmET5iqfy63jR
         XJLtQnFwpMQvReo9Tt5qxKgK7ZHN/u2vlG0DSacm1q1zpuhkHz++UUgK7yopEgnvx7g2
         Yv+0UhhaFF7mU1oGY3VUK/TeL8NlqRxBIw4bRI9oUkcGyed9nb+IjPAZRmd0WOV3O8yl
         v0DveK9WaeCz/SiYvoY5Knh/SB0z/Etb8F3MRVhO3HUF4JYZkBGl/c1F5tDmrk271b9r
         0A6Iga/4SYh6aXorYubQvi0ZJa6KmxRZDkV8Daj1Fy3qBnO3BZm3yZmCHFeEe6ZTil5g
         nxyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DY6DgfCc;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id e7si91047vko.4.2020.10.20.05.39.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Oct 2020 05:39:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id s22so989493pga.9
        for <kasan-dev@googlegroups.com>; Tue, 20 Oct 2020 05:39:36 -0700 (PDT)
X-Received: by 2002:a62:ee10:0:b029:142:2501:3972 with SMTP id
 e16-20020a62ee100000b029014225013972mr2480974pfi.55.1603197575998; Tue, 20
 Oct 2020 05:39:35 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com> <001de82050c77c5b49aab8ce2adcc7ed7d93e7ad.1602708025.git.andreyknvl@google.com>
 <20201020062248.1966-1-hdanton@sina.com>
In-Reply-To: <20201020062248.1966-1-hdanton@sina.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Oct 2020 14:39:24 +0200
Message-ID: <CAAeHK+wQWv7w9w2TgdvNFp_5KdjMF3+R1vLNDTJiWMZQ+hBbzw@mail.gmail.com>
Subject: Re: [PATCH RFC 7/8] arm64: kasan: Add system_supports_tags helper
To: Hillf Danton <hdanton@sina.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DY6DgfCc;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Oct 20, 2020 at 8:23 AM Hillf Danton <hdanton@sina.com> wrote:
>
> On Wed, 14 Oct 2020 22:44:35 +0200
> >
> >  #ifdef CONFIG_KASAN_HW_TAGS
> > +#define arch_system_supports_tags()          system_supports_mte()
>
> s/system_supports/support/ in order to look more like the brother of
>
> >  #define arch_init_tags(max_tag)                      mte_init_tags(max_tag)

Well, init_tags() does initialize tags, but supports_tags() doesn't
not enable support for tags, and rather returns its status. So using
"support" here would be wrong from the English language standpoint.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwQWv7w9w2TgdvNFp_5KdjMF3%2BR1vLNDTJiWMZQ%2BhBbzw%40mail.gmail.com.
