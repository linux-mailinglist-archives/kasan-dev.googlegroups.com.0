Return-Path: <kasan-dev+bncBAABB3OOUP5QKGQELXXEGVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 239AC273113
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 19:48:31 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id e6sf13594199qtg.13
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 10:48:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600710510; cv=pass;
        d=google.com; s=arc-20160816;
        b=UsFyzSWyPJ5owo+IDAvc3oJvFQG2VM8fkT5DJoSKqNdK6Ms2HhGEoKcce3+v1U5yM6
         Dt/BrQpvqc7sUBS5yDLRVBg6uu6CqdAPkjdGcLra0F7p9vUkRSDT1ui5tGHb5y3/IzNu
         y5u5U1c80HpjzgGNcHz51TQyi/Xb0thkODQ6fgJiQwD/7iA81eSrs+UjZnHLzPtTWPU0
         o2KwaUhCnqhJLS+gppby5dzr5cZvkyyNCMgZ+HC9JSrwLimUXa7qWej/DzkQcbqWozg9
         ZsrrjOCDsG6ajQUPjN255tU91DjqAyxZGCn3ZovzD3FNNMgnrJa+tb9d94hdEZ0b6qt+
         yJBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=gTBaCcQcxXufj7hJpIT9tqkQJSi41qaCbU8jQSpTYcw=;
        b=bSU+/6OBYAGiwlXAMzFrgYDfMaDNijKgbPbQ5Yxu0yB8ANJN1ianP88nYp+sxhG3jQ
         ZBSnN4r77a0qyb3Qi4KIf5ln9D3v7H+N5fd7mRByRHsCCSriTc7HBvQtBHTOh6I5BSYZ
         gMcBi10GAynHBb+Jn2g5qMlTd/N79T2XV5YSTDhEWev7bmiygWSuznimNstqfpOkYajl
         J9jZ26yXEuxnktipnPGW9zMBWrbSTbYEez7JO1alwEPBIbobCUI++LssZfYcqGqgb3Vt
         iG+55M4/oIDOnZM76hdHUQ49fkGTCiNxEeSO6Clu7g6Vl/YXdIaUZ7PyQaPta9e2zW76
         +TNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=T4oPJpc3;
       spf=pass (google.com: domain of srs0=dqke=c6=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=dqke=C6=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gTBaCcQcxXufj7hJpIT9tqkQJSi41qaCbU8jQSpTYcw=;
        b=Np9FzCEdn9tgD9ws0EOULH9ya9/5ULNQGt7zukRahhui7UU5b6WS3hk/TjpIvJCFPA
         4DLGfzvhd2Fehu7Ll68LAqtypzaWY6j6ry87IG8Do50cC4wHcNSEtZVlbS6K1neDqt4c
         qjkBSW1roR8NbjqPGwW181aEstwYHqHE1oW9A9sXUko5wn3uWbV3gu76sbJgHaefvxyI
         5aHRzqRit0sBW4YS/Wit5hMXSLbQy8E2bpoJfROKL7v6v322DmoLnJ3zzrp6ePfwcnaF
         C45nuuZhn20/dR1qhCAHLpkH4xm8257Zt4CQku7aw3NvNEx+5c50FCacKamE0SDd/XA8
         qEGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gTBaCcQcxXufj7hJpIT9tqkQJSi41qaCbU8jQSpTYcw=;
        b=XS4K8lzJenMLELuSUa8ksF2ey3Sbeieq6jT66lqeuzGAnMIFtELNTTx4PZjSMPqRyx
         hmxqr6wFpPzODsTXcbrY7Kvnzy2VTB1fIA9UFfhkeQbfqEXIo3vIs/Kw7Z6QOPtKuPXA
         9kE3vY+gijH/rocobfhUgg4U75VgnpSXD8JF097GLeJ8bijrkhNz6X7sXIpzgKreqovc
         MDkfjA06vLQpWNjN1Afj2gamB2FRzUkFRz5RONd+JooOgvAM5iT+MxNXIU0hTtU82KNR
         dGKGocfFCd0wzQvMPw6pE3wTvD1vdyZtQVkTpSJAkcf6DYDxAvmctwW+/YvqBYczPvy9
         bn5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5313VuuG0OaAP8E9vE66dtkirv4SvgY0pUW8f9099DB9weIrQeXa
	2gUi8zGvNUJKedT1e3htR5I=
X-Google-Smtp-Source: ABdhPJwj9L7AG0ZtK3UxfkQ3Fj5lnA+GW647ilLoaLg0NlTTPkIdMSd12gaYvRZzVG+Acajqf4+NUQ==
X-Received: by 2002:a37:4e45:: with SMTP id c66mr1003282qkb.36.1600710509873;
        Mon, 21 Sep 2020 10:48:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:48c2:: with SMTP id v2ls3453950qvx.4.gmail; Mon, 21 Sep
 2020 10:48:29 -0700 (PDT)
X-Received: by 2002:a0c:a612:: with SMTP id s18mr1169054qva.37.1600710509386;
        Mon, 21 Sep 2020 10:48:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600710509; cv=none;
        d=google.com; s=arc-20160816;
        b=Yzf+GPXYDXLTLFnIcsfYCzrcA50q5TB5Ok/fTzB5PuYF1H0mSqDk55zr0SdrvIyitI
         rh7Nu0VIbFeBS85+pATv2ORryz3H19M/J8muTqT3ZQ9lfFUv9B9eawHyHrSVsesXu1nl
         YRrhFEDrsqbeuVqgsCQPcUu8CWVTE4rph9EG4aToBmxR43OEfi6Rb5JA4hBRjkNDGz7o
         Z/EPY3vN3BY8Aq0AfDmsiL20pzNtJ4V2QqKcA582OXOn49LX2UopA1/4/aFoecz5EfoP
         SGBe+gN0iNxnM7oB88531Oo0rX/yXsYg1oHhRl2aAY0m5aD3pQfhBk1OL9O4KNiYcPuj
         8eHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=9gMCgUPuqmsDOVX4JdDkewhoINxdoNAYr1tEhpDlJvQ=;
        b=AHyK0hDNYS5ikjPjFf4JJZpFvFOsUpLHET58xfKtByG3h3PIIqpQ5Whn0ajrjJbWI9
         urZVSZqaFHEBWD/l5EQsxwYZ24ZxkoNKQJgmKwCB1pLCZlByL9XXkvcICJrxdrfrRt8I
         TSZ8ObATU9DfqhRLQQ5D5nJFkE/3zOOQ88GdQnID9ufUrddg9hd1vFre8kH4xbbptgYB
         o9WI+0+1fws7oK/TUNH6wuF83uC3g7wnKy/NOFuryd1SsKxe9Y33OOtgSHaB6+uxIh3w
         vseLTO2gHky4s2+10zZZGEJI4WNCjWVn00sGKd8RhOLP4hfaO35dMVxVBck7q+K1XCSe
         XUJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=T4oPJpc3;
       spf=pass (google.com: domain of srs0=dqke=c6=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=dqke=C6=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a2si676274qkl.4.2020.09.21.10.48.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Sep 2020 10:48:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=dqke=c6=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 316392193E;
	Mon, 21 Sep 2020 17:48:28 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id D2957352303A; Mon, 21 Sep 2020 10:48:27 -0700 (PDT)
Date: Mon, 21 Sep 2020 10:48:27 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph Lameter <cl@linux.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Hillf Danton <hdanton@sina.com>, Ingo Molnar <mingo@redhat.com>,
	Jann Horn <jannh@google.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	SeongJae Park <sjpark@amazon.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>
Subject: Re: [PATCH v3 10/10] kfence: add test suite
Message-ID: <20200921174827.GG29330@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200921132611.1700350-1-elver@google.com>
 <20200921132611.1700350-11-elver@google.com>
 <20200921171325.GE29330@paulmck-ThinkPad-P72>
 <CANpmjNPiAvyn+oARU39yOx7zxMxV8JHiSS_41H+65D_-MKmk7A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPiAvyn+oARU39yOx7zxMxV8JHiSS_41H+65D_-MKmk7A@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=T4oPJpc3;       spf=pass
 (google.com: domain of srs0=dqke=c6=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=dqke=C6=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Sep 21, 2020 at 07:37:13PM +0200, Marco Elver wrote:
> On Mon, 21 Sep 2020 at 19:13, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Mon, Sep 21, 2020 at 03:26:11PM +0200, Marco Elver wrote:
> > > Add KFENCE test suite, testing various error detection scenarios. Makes
> > > use of KUnit for test organization. Since KFENCE's interface to obtain
> > > error reports is via the console, the test verifies that KFENCE outputs
> > > expected reports to the console.
> > >
> > > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > > Co-developed-by: Alexander Potapenko <glider@google.com>
> > > Signed-off-by: Alexander Potapenko <glider@google.com>
> > > Signed-off-by: Marco Elver <elver@google.com>
> >
> > [ . . . ]
> >
> > > +/* Test SLAB_TYPESAFE_BY_RCU works. */
> > > +static void test_memcache_typesafe_by_rcu(struct kunit *test)
> > > +{
> > > +     const size_t size = 32;
> > > +     struct expect_report expect = {
> > > +             .type = KFENCE_ERROR_UAF,
> > > +             .fn = test_memcache_typesafe_by_rcu,
> > > +     };
> > > +
> > > +     setup_test_cache(test, size, SLAB_TYPESAFE_BY_RCU, NULL);
> > > +     KUNIT_EXPECT_TRUE(test, test_cache); /* Want memcache. */
> > > +
> > > +     expect.addr = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
> > > +     *expect.addr = 42;
> > > +
> > > +     rcu_read_lock();
> > > +     test_free(expect.addr);
> > > +     KUNIT_EXPECT_EQ(test, *expect.addr, (char)42);
> > > +     rcu_read_unlock();
> >
> > It won't happen very often, but memory really could be freed at this point,
> > especially in CONFIG_RCU_STRICT_GRACE_PERIOD=y kernels ...
> 
> Ah, thanks for pointing it out.
> 
> > > +     /* No reports yet, memory should not have been freed on access. */
> > > +     KUNIT_EXPECT_FALSE(test, report_available());
> >
> > ... so the above statement needs to go before the rcu_read_unlock().
> 
> You mean the comment (and not the KUNIT_EXPECT_FALSE that no reports
> were generated), correct?
> 
> Admittedly, the whole comment is a bit imprecise, so I'll reword.

I freely confess that I did not research exactly what might generate
a report.  But if this KUNIT_EXPECT_FALSE() was just verifying that the
previous KUNIT_EXPECT_TRUE() did not trigger, then yes, the code is just
fine as it is.

							Thanx, Paul

> > > +     rcu_barrier(); /* Wait for free to happen. */
> >
> > But you are quite right that the memory is not -guaranteed- to be freed
> > until we get here.
> 
> Right, I'll update the comment.
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200921174827.GG29330%40paulmck-ThinkPad-P72.
