Return-Path: <kasan-dev+bncBDV37XP3XYDRBF4E3X5QKGQEZ7XN23I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 98636281611
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 17:07:05 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id 8sf1378766pfx.6
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Oct 2020 08:07:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601651224; cv=pass;
        d=google.com; s=arc-20160816;
        b=nXZmeHRdVa3DNJEGpbLEu6BHSVzQGlzNoSt6jg3Mb40mKMwVwdzqyQRIOyorGm17gh
         8UqdA/o/jf3eaPwOvAwitQkvi4oZwzrBUmyHSwCWkQGz9ueh4eyCxfLaQYJkmb0Pqfiq
         R29bwrA/Wqjb+jixxB3V4TswrGxMn5DxxgWaFvqjxKL56E/A22KBTqSfrkkitMrfLTqT
         6jaSCTDurwoDajk3mvUWcDsevm2kvjLW6s9bHYMYmF1zon2UyTT7YhXdglyQuQ4ARNfo
         AcBZueE97YCNaw8oWnTiCPDdmRDiEgx8k6skC1UhiNjja8mCgug47hTFte+UfKHePI//
         0L/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=54tDP/TbZQHbad3AjmNSCEVEEoJJKMyIm+Ic2wOZbp8=;
        b=RJmDd8BFXTB07CAvT8x3Mn22RmUDeHeO/kgkWgYz+5nYe2qJH4fdeNRIA7aRaPjNw7
         0ceznESSryaCu0/FLWJFJTL8wJvJvb8dm1KfXeiE8LBcyFyl35WS5+qmUCEUjRqQJ1Hf
         7AoFzBmo8T5I1xCPLLIh5A6DZ0797BqJMlyvuS2e687+vwwGIc8byIhgyXQeTr1S4vIm
         q4EyGsxKesfyRbWrMQnvAyq+2FKZHcab7OjtfPlnsz3wiOU0GjVFd4OONYTFrg4imK5d
         dtV6387N2V42ajIyxwEoq+SEteg6TkJt53Wx/PO1rmvv3MBHMGfUhB4ZicxvxkyjLsqj
         x5gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=54tDP/TbZQHbad3AjmNSCEVEEoJJKMyIm+Ic2wOZbp8=;
        b=M8nQvj7Qv4WdWKvaG8+AfqlJikFY6z1CtkLg3+R2pYJJ28pHqfRSgusbAPkH7Vobzi
         3AXBGLpeObLu1aeeKLoSFwFmPyHVsLZdUePEVMeqqjThOLWDbHkQZcFPFEFdyUU6pZOt
         0ra9X1B7gCqsX2klrFJzIDUU52qfm/HSCfIXL9YoWNO0cVbXQW5GrDB9uHfjq2PcoUUc
         cvxkOi731eOZnTYuvplEpSuFEhyF4QRLfjQ0SEDHOBiAzDXYWd+cnHpO7HvzFo+BbT1t
         MI/PALFJESIyz7d12Q5VtJeUidwNRtvyjg0nHOE1WyLmvkdI/lG4e5ifaJIkSMMeDrgN
         3VBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=54tDP/TbZQHbad3AjmNSCEVEEoJJKMyIm+Ic2wOZbp8=;
        b=G3lshmpXffk+/fToydAg3cdAxRO4GTi3EiwXHLa9UqXmnG73EopQ3e2FXSf70ZADTz
         eIJbvKjahQMLdOSNixEPdXvSj+92lS+IaLfsZ3THlT7Y92GiMebXtvRzAfnbnPUzR5tm
         P+8IICRK067XmJ/gDj42PX2/JmUoAz/rIz5ljczgnkEMgdGiLWLRJXs9DGV1eEwMKkIw
         x9oRHsfMWbCSOkAuo1CNDJB7Q3SG20nLGBIY257tzO6Bgju9EDlhFeRjYHL683V/fXhg
         XuSceaIO9rPD9SRevspftNEjnoBpAfne/ISXS87wa8y8g9MymKq5qhZc2k1Sq0WEwxXv
         U88w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5329/WXWK/2Dage2uYQtHd0v2Hu84rAnWg9m+v7bhcbvLjioVkKV
	hRxGX5hkFwYbGpwo/Ndr3L4=
X-Google-Smtp-Source: ABdhPJyNmwxAo9ljfvxOT8angLyAK0ADW0mtDwa4mONKfHwnDGy0U4EMrA4mOXhe5vJed5XmL40uKA==
X-Received: by 2002:a63:c84d:: with SMTP id l13mr2579994pgi.3.1601651224178;
        Fri, 02 Oct 2020 08:07:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:714a:: with SMTP id g10ls1451505pjs.2.canary-gmail;
 Fri, 02 Oct 2020 08:07:02 -0700 (PDT)
X-Received: by 2002:a17:90a:db0f:: with SMTP id g15mr3198500pjv.145.1601651222653;
        Fri, 02 Oct 2020 08:07:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601651222; cv=none;
        d=google.com; s=arc-20160816;
        b=Mcsuu1UbP97pw6qiRFuWUT+6AvQqRvsjPdPpmO8BsHxhdxL5FMrg+qqJ/34sLcU82e
         jC7lcQ0I8BAdl2NSEcFfFBm0JoXktHxhhR1GUOWun+XmxilP5FcUrzt49zt3pwZ89Qyw
         COReauhOaXlq2o+1fWYiVevgyyWFMrEBVra6bqRH7gWvZhNbGQUU4koafZjeEw83++9A
         BDJMwNXLY5/llOyAGc8Y2SeM67kMnENAVKHerKr76cTISDf6BB/+qYjwwR3doYExy/KB
         0u0Shc5Rc/BXN6gWcM0Ject8M7ucnPy3sV3pggNbkQQ/ARJ1vsjqDPQkEJkFZt6DNVx6
         NnzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=aXoY4wv1t31SpFa5r7xA33qM0R5wn6W6imB4roqYL/M=;
        b=N82Rww97wrXa2JVHG7U5dDwRA/ajKRuryccBsvN/EsAudpxCIadiHry/sonNblwbX+
         1Puo0E7065fl2ZHBl0mjDE8CNNvobaAwuV+bqvrF/m16tNXUTHupPep3CI8VuYsJGUTn
         MUXFJOy+DJguYt4UrCyZ6KiMWN0OTn0pL4YZDPKnpVpqdsD0wXfndvhNnoOen9uIc+C0
         4tf2lIbl4yk0HJ/kR+zGzbhvPzcyx3AKycjEFJmp5Z1NUDwr5neHXKwDhbNB9PAS7O49
         j83uq6buqqIvv9g8fSe0t1Ek7jhvxnnQQplWvwjh5TczxiB73GAQuJWknO2RYCpkNdy7
         d6jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h10si28652pgm.4.2020.10.02.08.07.02
        for <kasan-dev@googlegroups.com>;
        Fri, 02 Oct 2020 08:07:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B12B41396;
	Fri,  2 Oct 2020 08:06:56 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.49.154])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 45F5C3F73B;
	Fri,  2 Oct 2020 08:06:50 -0700 (PDT)
Date: Fri, 2 Oct 2020 16:06:43 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Jann Horn <jannh@google.com>, Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	"H . Peter Anvin" <hpa@zytor.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph Lameter <cl@linux.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Rientjes <rientjes@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Hillf Danton <hdanton@sina.com>, Ingo Molnar <mingo@redhat.com>,
	Jonathan.Cameron@huawei.com, Jonathan Corbet <corbet@lwn.net>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	kernel list <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux-MM <linux-mm@kvack.org>, SeongJae Park <sjpark@amazon.de>
Subject: Re: [PATCH v4 01/11] mm: add Kernel Electric-Fence infrastructure
Message-ID: <20201002150643.GA5601@C02TD0UTHF1T.local>
References: <20200929133814.2834621-1-elver@google.com>
 <20200929133814.2834621-2-elver@google.com>
 <CAG48ez3+_K6YXoXgKBkB8AMeSQj++Mxi5u2OT--B+mJgE7Cyfg@mail.gmail.com>
 <CAG48ez1MQks2na23g_q4=ADrjMYjRjiw+9k_Wp9hwGovFzZ01A@mail.gmail.com>
 <CACT4Y+a3hLF1ph1fw7xVz1bQDNKL8W0s6pXe7aKm9wTNrJH3=w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+a3hLF1ph1fw7xVz1bQDNKL8W0s6pXe7aKm9wTNrJH3=w@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Oct 02, 2020 at 04:22:59PM +0200, Dmitry Vyukov wrote:
> On Fri, Oct 2, 2020 at 9:54 AM Jann Horn <jannh@google.com> wrote:
> >
> > On Fri, Oct 2, 2020 at 8:33 AM Jann Horn <jannh@google.com> wrote:
> > > On Tue, Sep 29, 2020 at 3:38 PM Marco Elver <elver@google.com> wrote:
> > > > This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> > > > low-overhead sampling-based memory safety error detector of heap
> > > > use-after-free, invalid-free, and out-of-bounds access errors.
> > > >
> > > > KFENCE is designed to be enabled in production kernels, and has near
> > > > zero performance overhead. Compared to KASAN, KFENCE trades performance
> > > > for precision. The main motivation behind KFENCE's design, is that with
> > > > enough total uptime KFENCE will detect bugs in code paths not typically
> > > > exercised by non-production test workloads. One way to quickly achieve a
> > > > large enough total uptime is when the tool is deployed across a large
> > > > fleet of machines.
> > [...]
> > > > +/*
> > > > + * The pool of pages used for guard pages and objects. If supported, allocated
> > > > + * statically, so that is_kfence_address() avoids a pointer load, and simply
> > > > + * compares against a constant address. Assume that if KFENCE is compiled into
> > > > + * the kernel, it is usually enabled, and the space is to be allocated one way
> > > > + * or another.
> > > > + */

> KFENCE needs the range to be covered by struct page's and that's what
> creates problems for arm64. But I would assume most other users don't
> need that.

I've said this in a few other sub-threads, but the issue being
attributed to arm64 is a red herring, and indicates a more fundamental
issue that also applies to x86, which will introduce a regression for
existing correctly-written code. I don't think that's acceptable for a
feature expected to be deployed in production kernels, especially given
that the failures are going to be non-deterministic and hard to debug.

The code in question is mostly going to be in drivers, and it's very
likely you may not hit it in local testing.

If it is critical to avoid a pointer load here, then we need to either:

* Build some infrastructure for patching constants. The x86 static_call
  work is vaguely the right shape for this. Then we can place the KFENCE
  region anywhere (e.g. within the linear/direct map), and potentially
  dynamically allocate it.

* Go audit usage of {page,phys}_to_virt() to find any va->{page,pa}->va
  round-trips, and go modify that code to do something else which avoids
  a round-trip. When I last looked at this it didn't seem viable in
  general since in many cases the physcial address was the only piece of
  information which was retained.

I'd be really curious to see how using an immediate compares to loading
an __ro_after_init pointer value.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201002150643.GA5601%40C02TD0UTHF1T.local.
