Return-Path: <kasan-dev+bncBDAOJ6534YNBBTEYXG4AMGQEKTFYOEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8ACAF99E4F8
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 13:04:46 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-43127097727sf18919655e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 04:04:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728990286; cv=pass;
        d=google.com; s=arc-20240605;
        b=d7QWw5Hfw2axe+diFVEwQpPDCRdZsqjnA2xt2cvT9psGspGwiY++MzmNLu2XlE4QJZ
         MgH9OH7FNRuLglm+y1XYyo+4CTc6Ok5LiryzJsMZ5539pIaMLesQw0IGaoxLcwNXMiAA
         JoRLHYH69YGXG4cKzP/Hb+kgbNWYwRNq/ix1txvfJ1nMNno7Gp/hYsndznL5qH815bot
         kfoxSPjxtZ99S5G686NvA9LA466QHTuETbYD+zrSbsiZDAmIb0sJkQ+d9n9vKQAiPcJP
         i16wTjm6JWPscvbP43jmke7dqoNaf9uYzJmfocJG6HCq6eR7Dykt7CHmxID3VZR5YSCL
         VwBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=GXAN5P/1garE205HqCeSXSjL9ZocIPOMboyaMr4ZRVg=;
        fh=Lky1/thmyWH26qTkkW4WT70SH7aqgHYVuSH+kr39+FQ=;
        b=BWITm3Md+b1bb2Qc4XXXGstctxM8tLEQAu82OLJUCyWrURc0tvFdyZAL7moVqUuKYv
         WLRvBFfwJ6SGSi/pLL5daSg3uKyeGTQld8EQt1sDrhvLYswm6PyMXMJ3XPYtQJHgNrQE
         tDsmjynd6Kd44oF75xgfyJnt3itpf5VVZ1vFsDb7IaocPko/q1m6ei/mNeQc3b4d0pNv
         +yq4CUuO487aHY/SElPXzvENQzhy4PLEkdRkZVwMa1OkilLLtMLsbTztXNDR2wEUZOku
         67F/C281pMRtnN7ebrSZ/su3R8Sc7JCvZn8ED6xVYvJWi7YHJYvUAPeIfOUt2OMXznRn
         XdzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NDN75EX5;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728990286; x=1729595086; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GXAN5P/1garE205HqCeSXSjL9ZocIPOMboyaMr4ZRVg=;
        b=KPfX5JaXCWpS9kqcJSuub1zqD59rmOBmshca6Y6uCINrMUvtsuRAjNL7EQdSjzNORb
         X5SXMpivsPcE+dfEv7G3yQ6WN/EN9sTNTDEbPxVL6qZXDRBDLe2Ll/gNccODS/4l/W5Q
         lBQmDjB2uezWhZ1G86VnSBCL7g0/qv+KO6SBfn7JPcIx1aV8+DnwBHMKWEKvLp+TNq/4
         E6FaTipLCDTcYJGCL5dP2vdc1RKG4815dCUQh7MCJVRjdlRH5KE62YZUmJs4mFQqgapB
         OMm8y/unrZYsWrqxdHK+wkg0kJLk3pOK3mU8Y5xwhZYHTIKj5izLixD68RO7E/IaYRoA
         CcYw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728990286; x=1729595086; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GXAN5P/1garE205HqCeSXSjL9ZocIPOMboyaMr4ZRVg=;
        b=gZmKoYAPYHg+y+FeDdIEDORgyMCDw5vtK+pMY14jHMx//67QMX/s177brqvHfDrqo1
         sP1br+BcxBkjrYOH7x0O1iISd+adiRdnSlSeZpHo2fWDeS1w35ul9BiK9G8nqyrTYR3E
         +0QmDSlp9Wzr177NhCVD/d39XNeY5OBMLdmpaer0bLJI9sUq4oU6Wzw+FGMDoyIx0hVP
         f0y+sb/8XAp7UCxQqBoawMq/brcKjKCp7njOHypSiijUASz/88hmm3FKzLVHxfRvy9IZ
         tro//lsYpmm8jBf9XvaztKnwX1KIR5zjYaPVA0jlj7Mv4w1YY7F2IUWXGTCIJO+HqmdW
         zfwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728990286; x=1729595086;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GXAN5P/1garE205HqCeSXSjL9ZocIPOMboyaMr4ZRVg=;
        b=A+3SIlT6l8rbKFjlCfT471CFbpK4P1xPwTFPXjed+05BKNjwblFEkBqBcRNTRxQ0Zz
         jcjP0gtWW7NjZmXUICSNQB6AgnLrMAsfo6iMIIOAYtbXC7O6zTPP9Tvng7FdiPpsd/PB
         bt9lQSHH8AvH0qR8gHGi0TKkllJrNCMPSfw+nJITdOxKMs7RXSJAs9eimkkDdjJov/sr
         2WYEkWWb6AshINxSc+BMLaC0r2gmK6jpuoUrBdcLc6l/MIo0k6YHIe9CaHArbYIq4Z2K
         8QoD1zv79UChTYb+TUH8qU7MhoHRVpt+IBazEXMUpzptqgJxB05w6U+Uh9LhtriJwJu6
         zw9A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUwuJfkL7MGs4O1YpFTyjZmHTsvu+qOtlSHmj19Q8gHGcCOHvIt5BhM28XzGMAe0jcZea9H3A==@lfdr.de
X-Gm-Message-State: AOJu0Yw7UtTxEmK3q4YRN5zGCC1c6tFeGLY/R6ptqQrzRjMKopYVopUy
	+fKV6vmPLenkAwBcowZZmm/wN+R8Ls3+ZcbqS7TANrNYVX+9SL6i
X-Google-Smtp-Source: AGHT+IERbCuRqF76kEF/2NuXd6jdlqgW+vlw+xmTIyRPHRIAiwz9lz12wxYgPwJj0bb9ZWeZ1AfRkQ==
X-Received: by 2002:a05:600c:3555:b0:42c:bb96:340e with SMTP id 5b1f17b1804b1-4311df56158mr114723695e9.31.1728990285129;
        Tue, 15 Oct 2024 04:04:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6a4d:0:b0:37d:3a51:d650 with SMTP id ffacd0b85a97d-37d4823b202ls1359374f8f.2.-pod-prod-03-eu;
 Tue, 15 Oct 2024 04:04:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWROe68wPpNRJvltHCBONs+H8aP4IzYfkdKscAwMwkFJxepVluUD6rGkyyT3kQiuerUgF1+26Z2t3E=@googlegroups.com
X-Received: by 2002:a05:600c:4f08:b0:42c:b950:680a with SMTP id 5b1f17b1804b1-4311df13433mr112602385e9.20.1728990283208;
        Tue, 15 Oct 2024 04:04:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728990283; cv=none;
        d=google.com; s=arc-20240605;
        b=Z5jEryIxER8jRbT+Wc71uqEHgHN6n/Y8Y5NcRpBtgRcAQOj9irLw5eW7mCTp8y0eui
         4gsrCnqVwjtuuqyjmiAfYCZ90w5V6Zv93girGHGgeHWFsvTJMizP2cQccmjB136FD4GW
         uhQfHQlPdBGunjPVb13aPty+0pSG9HRse0IJRQ6z7AK7I5WBocIcijHpgvmtxP/BHKo8
         RGVWKCAAD9oWF44upnn2jFg+suPDUNTbIO++1Vxr2A2h/TL52kCvDV7SHQsiKB17R4iW
         UvTv2sdS+ByGC8hminjX9CjzSgL3cc+o+9q7l/fg7gxvf1T9ecVBigblf4Cq/0EVfVjo
         aFkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=nWOPVDT6rjztxkkkBYeqnJi9hJ5pL7jdILVFzXtkOpE=;
        fh=bo+i19gPaKG3610qlRhM1NKmlaIB6k7e8EAa9u72ZCc=;
        b=N1P1gYwzceb+d7HpIKjvD6OMX0i6ZZDLWxiP+5ywznDk4BkxlX/l9BZzPXUcse+5/p
         7uO4OUJJWa+mfsEAGsPNoSUwHqhrU9Qlll+M6wNpFoSJNu23PF/rlGiQ43TgtiFYo4iL
         /p/3cuQ+12Z6SO5hzqpy4EMpYJP75ATGlTkyB/XyqfeYBurQEnJe/xvzDz6pE+Qv9cU5
         qMKgEaUR0Bsmq7irHkBTs23tm0W8TAhTOFlsXRI6d6WPPuCc/UK7MrhBt6WX7mFtmuWf
         esdjw76ll5jm/MK46qrLDDK7MSH//zEkfjtFo+nshgIAzc71p/RWXel91UaV9lh1zE+V
         d4Ig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NDN75EX5;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x229.google.com (mail-lj1-x229.google.com. [2a00:1450:4864:20::229])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4314755039esi219835e9.0.2024.10.15.04.04.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Oct 2024 04:04:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::229 as permitted sender) client-ip=2a00:1450:4864:20::229;
Received: by mail-lj1-x229.google.com with SMTP id 38308e7fff4ca-2fb56cb61baso11071111fa.1
        for <kasan-dev@googlegroups.com>; Tue, 15 Oct 2024 04:04:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVGAZ56FqAYrkMjrQ6yYflCd+IeaQ5pXoV5MrxDGNv1UjJ0uphkeeCUQHPSuUJQdr80nNWhlt4wQ+w=@googlegroups.com
X-Received: by 2002:a05:651c:220e:b0:2fb:51f3:9212 with SMTP id
 38308e7fff4ca-2fb51f39559mr31642441fa.6.1728990282008; Tue, 15 Oct 2024
 04:04:42 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZfs6bwdxkKPWWdNCjFH6H6hs0pFjaic12=HgB4b=Vv-xw@mail.gmail.com>
 <20241011035310.2982017-1-snovitoll@gmail.com> <CA+fCnZfznvJ-zaJg+Oeddt7OOPhnvkJ4z4N35rq5KXx2N=HBFw@mail.gmail.com>
In-Reply-To: <CA+fCnZfznvJ-zaJg+Oeddt7OOPhnvkJ4z4N35rq5KXx2N=HBFw@mail.gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Tue, 15 Oct 2024 16:05:37 +0500
Message-ID: <CACzwLxiAnGZaDMnKYU3+NKwuHVmk70OYTsBz=SZEYCV8zSn5GQ@mail.gmail.com>
Subject: Re: [PATCH v6] mm, kasan, kmsan: copy_from/to_kernel_nofault
To: akpm@linux-foundation.org
Cc: bpf@vger.kernel.org, Andrey Konovalov <andreyknvl@gmail.com>, dvyukov@google.com, 
	elver@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, ryabinin.a.a@gmail.com, 
	syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com, 
	vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NDN75EX5;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::229
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Sun, Oct 13, 2024 at 3:45=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Fri, Oct 11, 2024 at 5:52=E2=80=AFAM Sabyrzhan Tasbolatov
> <snovitoll@gmail.com> wrote:
> >
> > Instrument copy_from_kernel_nofault() with KMSAN for uninitialized kern=
el
> > memory check and copy_to_kernel_nofault() with KASAN, KCSAN to detect
> > the memory corruption.
> >
> > syzbot reported that bpf_probe_read_kernel() kernel helper triggered
> > KASAN report via kasan_check_range() which is not the expected behaviou=
r
> > as copy_from_kernel_nofault() is meant to be a non-faulting helper.
> >
> > Solution is, suggested by Marco Elver, to replace KASAN, KCSAN check in
> > copy_from_kernel_nofault() with KMSAN detection of copying uninitilaize=
d
> > kernel memory. In copy_to_kernel_nofault() we can retain
> > instrument_write() explicitly for the memory corruption instrumentation=
.
>
> For future reference: please write commit messages in a way that is
> readable standalone. I.e. without obscured references to the
> discussions or problems in the previous versions of the patch. It's
> fine to give such references in itself, but you need to give enough
> context in the commit message to make it understandable without
> looking up those discussions.
>
> > copy_to_kernel_nofault() is tested on x86_64 and arm64 with
> > CONFIG_KASAN_SW_TAGS. On arm64 with CONFIG_KASAN_HW_TAGS,
> > kunit test currently fails. Need more clarification on it.
> >
> > Link: https://lore.kernel.org/linux-mm/CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1=
X7qeeeAp_6yKjwKo8iw@mail.gmail.com/
> > Reviewed-by: Marco Elver <elver@google.com>
> > Reported-by: syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com
> > Closes: https://syzkaller.appspot.com/bug?extid=3D61123a5daeb9f7454599
> > Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> > Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D210505
> > Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> > ---
> > v2:
> > - squashed previous submitted in -mm tree 2 patches based on Linus tree
> > v3:
> > - moved checks to *_nofault_loop macros per Marco's comments
> > - edited the commit message
> > v4:
> > - replaced Suggested-by with Reviewed-by
> > v5:
> > - addressed Andrey's comment on deleting CONFIG_KASAN_HW_TAGS check in
> >   mm/kasan/kasan_test_c.c
> > - added explanatory comment in kasan_test_c.c
> > - added Suggested-by: Marco Elver back per Andrew's comment.
> > v6:
> > - deleted checks KASAN_TAG_MIN, KASAN_TAG_KERNEL per Andrey's comment.
> > - added empty line before kfree.
> > ---
> >  mm/kasan/kasan_test_c.c | 34 ++++++++++++++++++++++++++++++++++
> >  mm/kmsan/kmsan_test.c   | 17 +++++++++++++++++
> >  mm/maccess.c            | 10 ++++++++--
> >  3 files changed, 59 insertions(+), 2 deletions(-)
> >
> > diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> > index a181e4780d9d..716f2cac9708 100644
> > --- a/mm/kasan/kasan_test_c.c
> > +++ b/mm/kasan/kasan_test_c.c
> > @@ -1954,6 +1954,39 @@ static void rust_uaf(struct kunit *test)
> >         KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
> >  }
> >
> > +static void copy_to_kernel_nofault_oob(struct kunit *test)
> > +{
> > +       char *ptr;
> > +       char buf[128];
> > +       size_t size =3D sizeof(buf);
> > +
> > +       /* This test currently fails with the HW_TAGS mode.
> > +        * The reason is unknown and needs to be investigated. */
> > +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_HW_TAGS);
> > +
> > +       ptr =3D kmalloc(size - KASAN_GRANULE_SIZE, GFP_KERNEL);
> > +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> > +       OPTIMIZER_HIDE_VAR(ptr);
> > +
> > +       /*
> > +       * We test copy_to_kernel_nofault() to detect corrupted memory t=
hat is
> > +       * being written into the kernel. In contrast, copy_from_kernel_=
nofault()
> > +       * is primarily used in kernel helper functions where the source=
 address
> > +       * might be random or uninitialized. Applying KASAN instrumentat=
ion to
> > +       * copy_from_kernel_nofault() could lead to false positives.
> > +       * By focusing KASAN checks only on copy_to_kernel_nofault(),
> > +       * we ensure that only valid memory is written to the kernel,
> > +       * minimizing the risk of kernel corruption while avoiding
> > +       * false positives in the reverse case.
> > +       */
> > +       KUNIT_EXPECT_KASAN_FAIL(test,
> > +               copy_to_kernel_nofault(&buf[0], ptr, size));
> > +       KUNIT_EXPECT_KASAN_FAIL(test,
> > +               copy_to_kernel_nofault(ptr, &buf[0], size));
> > +
> > +       kfree(ptr);
> > +}
> > +
> >  static struct kunit_case kasan_kunit_test_cases[] =3D {
> >         KUNIT_CASE(kmalloc_oob_right),
> >         KUNIT_CASE(kmalloc_oob_left),
> > @@ -2027,6 +2060,7 @@ static struct kunit_case kasan_kunit_test_cases[]=
 =3D {
> >         KUNIT_CASE(match_all_not_assigned),
> >         KUNIT_CASE(match_all_ptr_tag),
> >         KUNIT_CASE(match_all_mem_tag),
> > +       KUNIT_CASE(copy_to_kernel_nofault_oob),
> >         KUNIT_CASE(rust_uaf),
> >         {}
> >  };
> > diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> > index 13236d579eba..9733a22c46c1 100644
> > --- a/mm/kmsan/kmsan_test.c
> > +++ b/mm/kmsan/kmsan_test.c
> > @@ -640,6 +640,22 @@ static void test_unpoison_memory(struct kunit *tes=
t)
> >         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> >  }
> >
> > +static void test_copy_from_kernel_nofault(struct kunit *test)
> > +{
> > +       long ret;
> > +       char buf[4], src[4];
> > +       size_t size =3D sizeof(buf);
> > +
> > +       EXPECTATION_UNINIT_VALUE_FN(expect, "copy_from_kernel_nofault")=
;
> > +       kunit_info(
> > +               test,
> > +               "testing copy_from_kernel_nofault with uninitialized me=
mory\n");
> > +
> > +       ret =3D copy_from_kernel_nofault((char *)&buf[0], (char *)&src[=
0], size);
> > +       USE(ret);
> > +       KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> > +}
> > +
> >  static struct kunit_case kmsan_test_cases[] =3D {
> >         KUNIT_CASE(test_uninit_kmalloc),
> >         KUNIT_CASE(test_init_kmalloc),
> > @@ -664,6 +680,7 @@ static struct kunit_case kmsan_test_cases[] =3D {
> >         KUNIT_CASE(test_long_origin_chain),
> >         KUNIT_CASE(test_stackdepot_roundtrip),
> >         KUNIT_CASE(test_unpoison_memory),
> > +       KUNIT_CASE(test_copy_from_kernel_nofault),
> >         {},
> >  };
> >
> > diff --git a/mm/maccess.c b/mm/maccess.c
> > index 518a25667323..3ca55ec63a6a 100644
> > --- a/mm/maccess.c
> > +++ b/mm/maccess.c
> > @@ -13,9 +13,14 @@ bool __weak copy_from_kernel_nofault_allowed(const v=
oid *unsafe_src,
> >         return true;
> >  }
> >
> > +/*
> > + * The below only uses kmsan_check_memory() to ensure uninitialized ke=
rnel
> > + * memory isn't leaked.
> > + */
> >  #define copy_from_kernel_nofault_loop(dst, src, len, type, err_label) =
 \
> >         while (len >=3D sizeof(type)) {                                =
   \
> > -               __get_kernel_nofault(dst, src, type, err_label);       =
         \
> > +               __get_kernel_nofault(dst, src, type, err_label);       =
 \
> > +               kmsan_check_memory(src, sizeof(type));                 =
 \
> >                 dst +=3D sizeof(type);                                 =
   \
> >                 src +=3D sizeof(type);                                 =
   \
> >                 len -=3D sizeof(type);                                 =
   \
> > @@ -49,7 +54,8 @@ EXPORT_SYMBOL_GPL(copy_from_kernel_nofault);
> >
> >  #define copy_to_kernel_nofault_loop(dst, src, len, type, err_label)   =
 \
> >         while (len >=3D sizeof(type)) {                                =
   \
> > -               __put_kernel_nofault(dst, src, type, err_label);       =
         \
> > +               __put_kernel_nofault(dst, src, type, err_label);       =
 \
> > +               instrument_write(dst, sizeof(type));                   =
 \
> >                 dst +=3D sizeof(type);                                 =
   \
> >                 src +=3D sizeof(type);                                 =
   \
> >                 len -=3D sizeof(type);                                 =
   \
> > --
> > 2.34.1
> >
>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Tested-by: Andrey Konovalov <andreyknvl@gmail.com>
>
> For KASAN parts.

Andrew,

Please let me know if the last v6 is ready for -mm tree.

Previous version was removed here:
https://lore.kernel.org/mm-commits/20241010214955.DBEB7C4CEC5@smtp.kernel.o=
rg/

Hopefully, they won't conflict in mm/kasan/kasan_test_c.c per another patch=
:
https://lore.kernel.org/linux-mm/20241014025701.3096253-3-snovitoll@gmail.c=
om/

Thanks

>
> Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACzwLxiAnGZaDMnKYU3%2BNKwuHVmk70OYTsBz%3DSZEYCV8zSn5GQ%40mail.gm=
ail.com.
