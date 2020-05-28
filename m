Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBLNLX73AKGQE3WQLRQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F54C1E65AF
	for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 17:15:59 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id q1sf15487904oos.17
        for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 08:15:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590678958; cv=pass;
        d=google.com; s=arc-20160816;
        b=bZNKaohihuKflJEL+rG96618QZZ3mzQZBtHiibJIwQCvziULPqL8OQs+LjpnAvlmMy
         R2+soUqNmOHtHlJEvo1YXsDYNQvJ1jDz5rqWUKGUDXK3Nz7atYEwtbc9wtL52mHNtAAE
         V1VdImsDst4V3G/l7a0F7ZpBmVG1V7x77zsu4WGVCdayOS/IeW18quWrBBqx1l7bIvyC
         k33o1ZqKY2Iwjpo2p9edvyeYnZioW8oJUYTl/f+XGs/AQyRfBd1pf2MlK9PtPq00JHZN
         IBjsLz9FAsocmV6x8R4jEeOMLkCRG5ELxLLAbT9IdZhAGMsg1OlpwkPkdPLobE82JnTE
         ROCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HdtRhR+EkMbe7ZQTBtTXR4Vp6XVGREJLMCP0sO2nQwc=;
        b=a/AVj5YICMRxj4f3GM0Y5XaEV1LC3LyEHSHdPdn+P80fhxWeeKYwZFgJSu35XSAeHc
         YrqQstS2zljrwXSiB6OiDSZehgI8itEcesDw6Vn+QEAQ/5nUkfHqZnZ+U9XYPUXdGb+l
         Xgp1c3OqH2Nd1bte7h6+DCOjiZErSe+H0UIIlPEu/6D86d8RpZojm3kANDAheCAfWTTq
         2mSSVu143obePwj/hV6jJhlcKK+G6YSebK1NfJX1qJj0ZzLOH5nCUBq4SjCfrz9jV5dB
         5tLnRDRwR0dAP58bW6uOvht2ZSUFpM+60JipxqUjSl90iNX5aFS2HTSAuxODW9w6bnZ3
         8fhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=fOEq3QDb;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HdtRhR+EkMbe7ZQTBtTXR4Vp6XVGREJLMCP0sO2nQwc=;
        b=Sg/QtTkRBp6Ha2uRvZ+NzOdi6tDFLi5oqm4Nc+mDaeRe0dN9CzYsKnbaD8/Wwn0SMv
         zeGXXp8Dh5Ef1UJzv3UL55ZsbZEnAwNe7z38HL53o/oCky55SsH/e+NCc9Gn49+mc/DV
         S+aqGwc96fLMosxmXIQSt3u29RAl3hJXss+kTM7N2SuxHNF2I1NXCKzqdUsS8whO+vsn
         FY1+n0HAC5D+QZD4UZDAz4xoOshqYTjU/qDeKnOiB9qALV1vQt1QDONRilxV4VtXwqz3
         V9QWCJPYC+6DkpuaUdcxtjKLx4sFeRB9FZfyW88YE15mdcnZ3ntZfB54I+mSiwiqOE/T
         vVPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HdtRhR+EkMbe7ZQTBtTXR4Vp6XVGREJLMCP0sO2nQwc=;
        b=Z+9ru5sJgoYQmidpH4ZNKqlxS0e19C5WFqMswGd5AN3AU4//2DVX3ji2TqaUgKIIM3
         4kyb5TtutsMzB2W+EGhBn445J8wkKGb4BTuaaPcvQRMwGr0o0DXnkMli0BnA/vamfb1v
         9+zGymFLI2Q9Jis5bYVzyVob/eWrQIQ4A9ApMSlcvhbbPJtbRUTN1rv7wSqhjTrbod+8
         BSK8XKM5uFuvG86uLiatxCbeADiqxNJgxoh1ClKAYktplvvUdp1puabqNulqs4RZ0gwR
         briZ4AQ60PE620sGehewhPa6au2FK0txeHZSRciPe+nth48jUuATDUgW5ngn+mucy0OM
         J+jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532km9jIuu+yq68Rsjj2wxnTQ4TBN/nX5I8qQ7nwZZl6XVx0BuU/
	SqlXa7BgCYsIk9o6VDQDooA=
X-Google-Smtp-Source: ABdhPJybsz9+6OBHWRg51lAGfvPEyLvKKlx19kNFoW/EdmmxTcDwArt+wEao53DlDLDlTZP+rIhp7Q==
X-Received: by 2002:a4a:6b0b:: with SMTP id g11mr2854467ooc.6.1590678957769;
        Thu, 28 May 2020 08:15:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:10e:: with SMTP id b14ls522445oie.1.gmail; Thu, 28
 May 2020 08:15:57 -0700 (PDT)
X-Received: by 2002:aca:c6d3:: with SMTP id w202mr2683311oif.44.1590678957434;
        Thu, 28 May 2020 08:15:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590678957; cv=none;
        d=google.com; s=arc-20160816;
        b=XneEPfdcfYGbQzYkZxVcm5v2YsQGtFiUI/UUUXc7K/j+v1FdMjSfWGxJxPpXVenM7X
         sd818FgTvyOxpOFJsyhL1eDP3LunMoYOhlQB+V0RqFZUgsZ8o7erOK9zIg35tBlS+tQz
         QSxHaNCd0FTFctd+8BCVCd5MXbmMrQ82/+b4fVoxK7tYOh0N3r9MpGpKI+cjkjjyDdPC
         XHOu2rd+QTjR/hWB5pm4bra+Gk/sKuZsB4M+qyjH5WdRNvy632GSBUi9KufHw2q1uX+P
         0rNrHPQSNTTyrcAz//I7VkKSkpBq7Bv8SYE5z+PN6QLNrEAw9loF/XvnVC5+yMFGLBvn
         aN4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=eaKHhY3AUa1ooLcsW6eRoTXAlHKgXN40+Hk1wYZjsxc=;
        b=wRlHIGQ+TaB+RsP14Y0qupBw9qukjqyVDwktcB5mblcg/QUQOGyauNdgiUYKTMoygw
         90Q19s7TtdHdcjDb6X41B7s+7U9h038b9dtPd5AhubhtJ4xq5XTgnUlkjYoa9ELP34Ev
         pcmhIJ8c7OvBx1M/Fl9cFT83vwMYqIkaFkYTqfknIlsHouHfS0vuzJUKh0KLW6jV/xDL
         lEo5K/JFg9B+moGmRdPTHXEt8cRZFC/24O01faQSmPduKBmL0WRfQTkObvtIp5Ogz0Qe
         xcwq8qroZxZiOeB6cZrVELBtYXtG4e9oAQA/VGOfMYFD+4gZOsVzJiW+SsH3eHJASUNW
         wqZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=fOEq3QDb;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id o199si326200ooo.0.2020.05.28.08.15.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 May 2020 08:15:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id z80so3450102qka.0
        for <kasan-dev@googlegroups.com>; Thu, 28 May 2020 08:15:57 -0700 (PDT)
X-Received: by 2002:a37:db11:: with SMTP id e17mr3162812qki.336.1590678956890;
        Thu, 28 May 2020 08:15:56 -0700 (PDT)
Received: from lca.pw (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id x43sm1748343qtk.70.2020.05.28.08.15.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 May 2020 08:15:56 -0700 (PDT)
Date: Thu, 28 May 2020 11:15:54 -0400
From: Qian Cai <cai@lca.pw>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Leon Romanovsky <leonro@mellanox.com>,
	Leon Romanovsky <leon@kernel.org>,
	Randy Dunlap <rdunlap@infradead.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>
Subject: Re: [PATCH 2/3] kasan: move kasan_report() into report.c
Message-ID: <20200528151554.GC2702@lca.pw>
References: <29bd753d5ff5596425905b0b07f51153e2345cc1.1589297433.git.andreyknvl@google.com>
 <78a81fde6eeda9db72a7fd55fbc33173a515e4b1.1589297433.git.andreyknvl@google.com>
 <20200528134913.GA1810@lca.pw>
 <CAAeHK+zELpKm7QA7PCxRtvRDTCXpjef9wOcOuRwjc-RcT2HSiA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+zELpKm7QA7PCxRtvRDTCXpjef9wOcOuRwjc-RcT2HSiA@mail.gmail.com>
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=fOEq3QDb;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Thu, May 28, 2020 at 05:00:54PM +0200, 'Andrey Konovalov' via kasan-dev wrote:
> On Thu, May 28, 2020 at 3:49 PM Qian Cai <cai@lca.pw> wrote:
> >
> > On Tue, May 12, 2020 at 05:33:20PM +0200, 'Andrey Konovalov' via kasan-dev wrote:
> > > The kasan_report() functions belongs to report.c, as it's a common
> > > functions that does error reporting.
> > >
> > > Reported-by: Leon Romanovsky <leon@kernel.org>
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> >
> > Today's linux-next produced this with Clang 11.
> >
> > mm/kasan/report.o: warning: objtool: kasan_report()+0x8a: call to __stack_chk_fail() with UACCESS enabled
> >
> > kasan_report at mm/kasan/report.c:536
> 
> Hm, the first patch in the series ("kasan: consistently disable
> debugging features") disables stack protector for kasan files. Is that
> patch in linux-next?

Yes, it is there,

+CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)

It seems that will not work for Clang?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200528151554.GC2702%40lca.pw.
