Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXUB7D7QKGQEVPVOGGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id F3B5F2F3B5B
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 21:04:47 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id c21sf2333276pjr.8
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 12:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610481886; cv=pass;
        d=google.com; s=arc-20160816;
        b=qk+5sNY8s5BwEiOtcyC9jt6uG+Rd1J1AwJVS6mnLw1VZBqE4sO6YwMan00JHi7uxPX
         sF7pNeXUWEDQkYesJcJvatHzW0tEaaRuIhPYeUzbfP1Dr41zubAEZQ5v9OkgG9W2tw+r
         I5FCp3KvWFjQZqxyZGW/5t8WXq8Fr9Tk/CPL4PfW34ZXNV5autZs22pInpwBHqS/pNhF
         ko+nvHBrUT4XLn9vJexxWoNn4CIfN9AuomWdZ2/ToZPfsnd+5ZkisnkOhu3Dv+Difh9S
         Xq/s/AO+aI32tJ2Bisi1AV18gxvZxIHRigIYleeAMMOpyuRYXK6bwd5gDI1LKxpfCSDu
         SUng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/JJjDJHzuwCiKyF51G0cVxdOnngccBDJrZUoYTHhUIY=;
        b=pTuKEi6lvsxldqqC9JQafMnotb8/g1POHrgPOpWTbMXrZSohfmVFCJE5gL1gCW/i4k
         ++FXSzq9vwTw00VV3BPOUikgPhLSewa4EDw54mc/N9BqgWtjIqWGyb6keB3N4Pi+Ze+M
         6lI0ie4PMK86XjxuVf9XNm+j14BoE18zeGdRtKJcDx76TXs1xZpz70VKknZr5cbYh+Zy
         MiueMMW6zaTepbY2W69hqNI7NXnjontui5wbcsE6Pcz0ACS0JeJy9S56emtMPWHW7j5R
         Tq3p7kOhI4Ez22xeGPQmfKrnOZMn9gr70jSk3S0weN0u8ISvwrF/2X//giZHf8KhV5pg
         YM7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Cs+4su4T;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/JJjDJHzuwCiKyF51G0cVxdOnngccBDJrZUoYTHhUIY=;
        b=V1WVayMzRn2ifpoWSyJpjyvWq0SImFhfDI98O0QQsghAxdFKuztgTC/od77XhuruJ1
         8Th50nIIeCclE/T3yzrrKMTjOELgwFaaB6GFPvSgQgsflVXF5kiBqk0rUlMgS/yYA9mr
         itx7uw33M+3IyYBmHSAOhL2AviSr6HfQ73tLy7DEL0mhOWrHvoEKrm9cIF3VTbL8l/Zk
         h4fqVF990ReGrR+5oHkjsLfWWwelR8VOFli0AaWG60wL8/t7CN+tPDJERxl+jclWsj8s
         DMXpzJpOPw/2RfdeiHYLTDE0EbF4oXP9X57LSSIezkYvuyRpD6F2ZIssuUwWpo9c15h7
         nAxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/JJjDJHzuwCiKyF51G0cVxdOnngccBDJrZUoYTHhUIY=;
        b=FhOEawSEpUEVlAdyfn6b4rtXEEvDkSgd+jl/w+O2plNClwmplJdBqQYz3wCw2XRfPD
         tt4nHS/qjsGNrCcAo0vhnDiDeNlQ2+gc4elzZa2POcP6wz8AJtN19Povp9PR9o6Ccamo
         3igdbODOqLZ2qpt8ZbLMe7GyujeN4lgJZC+68e/wHLzSFxq7Q1vX+MMW2XkSD1yk+fM8
         +uNrsF8u6wBhjzHaY9KqpepGFgbuR4i4rMtXkHKSe03CDdIn0mN+TvyucD2ICNl509IO
         9UEoiAP1J7RYC4ovbluD/H1aufTLqYHx6rUZNEb0N31Gxzm2qcfDkFFjauSuJVQWf708
         MUEg==
X-Gm-Message-State: AOAM531yCq6fc59IJ4ezUmdsknanrOQhkbJBXN8ldkfb0cFxHlKKESXT
	QuqUAB8qUtmx2cZ7AQGW7BU=
X-Google-Smtp-Source: ABdhPJxkDJq1YDrRk4YXkkkSbI/qhCQNy9mCsxVsAoL4RvRVGLVXXl+pw+vs9/0YFLc50Rn1K7URXg==
X-Received: by 2002:aa7:8701:0:b029:19e:561:d476 with SMTP id b1-20020aa787010000b029019e0561d476mr669003pfo.2.1610481886720;
        Tue, 12 Jan 2021 12:04:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e287:: with SMTP id d7ls2112150pjz.0.gmail; Tue, 12
 Jan 2021 12:04:46 -0800 (PST)
X-Received: by 2002:a17:902:426:b029:db:65c4:dbf7 with SMTP id 35-20020a1709020426b02900db65c4dbf7mr843678ple.3.1610481886091;
        Tue, 12 Jan 2021 12:04:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610481886; cv=none;
        d=google.com; s=arc-20160816;
        b=IHH448tJrbUA7ELXJegzsS31b55plxiZHIonykKKJsBeA0Htge98VFPpUks8kmvPZF
         gEaHAbEpzvGyZgCrlEVT/5zQmdzz0IOJ/wYh7IrJbIUIoZYVv+v+sWHUl/rgQpX5HDo3
         YjZP1T2WeiqkZ+JKLCVPKfL9oSIkqvln8Pbh4J0SuAaOmH3VmFY048CteZBEbnXfxXRw
         jcyEjY9ehejoTunIO4zuqjLp/BmaQgpDZm6QCWvsDhC4i4stlNwDFvobKGPopE4aaYMk
         SUhLPn9zIz+0FR2I31LZXBs/SDoFGE//IuEyDHBC/b9a6Q/7YMxTKxxdhroaNgs6HrL/
         kKRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hLTG8Xi/M9/KLF1jIe2hcQQ+UFUOXooQujW3N5lnPGo=;
        b=D5mu4fq9PVP9/GuzNeeJrjvqI8uferw3F70EiCq9ylzYtF/my1tM1zDDMSqMc79WjT
         616NTkyqYkFXbmfBguoC6hWdhnqhLlOEDEHh2/HZ4sOTVygoZ+xWPPu2tVLy3Fg0nwEj
         +wNU7wmJtSvsKdkSIdFNGYdU4Dkp9ki3s2ZOJrp4ERuFrANtuDktXXjt/pAiisfaEsio
         PohPZCWO9AkT/LHmDDetZPqEklG2NeDMzi9aLpyXiNExHGo36UYN56XQeTNZZIiPHY6x
         uBa0gFtXRB123hpZqGrA7wlqVdlDA5Sjw8S4Atc5tI3nJK/XHmhHrDlDrUX3tTZQ6jZf
         a1sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Cs+4su4T;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x102b.google.com (mail-pj1-x102b.google.com. [2607:f8b0:4864:20::102b])
        by gmr-mx.google.com with ESMTPS id z2si247030pjq.0.2021.01.12.12.04.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 12:04:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102b as permitted sender) client-ip=2607:f8b0:4864:20::102b;
Received: by mail-pj1-x102b.google.com with SMTP id u4so2382411pjn.4
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 12:04:46 -0800 (PST)
X-Received: by 2002:a17:902:c144:b029:dc:292e:a8a1 with SMTP id
 4-20020a170902c144b02900dc292ea8a1mr826431plj.13.1610481885659; Tue, 12 Jan
 2021 12:04:45 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <9a4f47fe8717b4b249591b307cdd1f26c46dcb82.1609871239.git.andreyknvl@google.com>
 <CAG_fn=X0YY8+FUWWyLqGUu5Z6-eEaSAOVGYj9PKzhzqyA1BvsA@mail.gmail.com>
In-Reply-To: <CAG_fn=X0YY8+FUWWyLqGUu5Z6-eEaSAOVGYj9PKzhzqyA1BvsA@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 21:04:34 +0100
Message-ID: <CAAeHK+wv4bZxSx4c+mjttRmhPFb2s0LM3Cey_GxfkVhxmgdsGQ@mail.gmail.com>
Subject: Re: [PATCH 08/11] kasan: adopt kmalloc_uaf2 test to HW_TAGS mode
To: Alexander Potapenko <glider@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Cs+4su4T;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102b
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

On Tue, Jan 12, 2021 at 9:26 AM Alexander Potapenko <glider@google.com> wrote:
>
> Nit: s/adopt/adapt in the title.
>
>
> > +again:
> >         ptr1 = kmalloc(size, GFP_KERNEL);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
> >
> > @@ -384,6 +386,13 @@ static void kmalloc_uaf2(struct kunit *test)
> >         ptr2 = kmalloc(size, GFP_KERNEL);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
> >
> > +       /*
> > +        * For tag-based KASAN ptr1 and ptr2 tags might happen to be the same.
> > +        * Allow up to 4 attempts at generating different tags.
> > +        */
> > +       if (!IS_ENABLED(CONFIG_KASAN_GENERIC) && ptr1 == ptr2 && counter++ < 4)
> > +               goto again;
> > +
>
> Looks like we are leaking memory allocated for ptr2 here?

Will fix in v2, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bwv4bZxSx4c%2BmjttRmhPFb2s0LM3Cey_GxfkVhxmgdsGQ%40mail.gmail.com.
