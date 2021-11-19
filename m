Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWNP4CGAMGQEQUPWKGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AF2A457825
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 22:32:11 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id n18-20020a4ad132000000b002c64a9d89a4sf3499420oor.4
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 13:32:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637357530; cv=pass;
        d=google.com; s=arc-20160816;
        b=PitqQqAmZrhY/lx6kMqyEkTydCW+kjes4y7zvGLm33glCbPDR/nHyFnb1VZPm/t6ij
         nPZ5Cz13n/TVAH6ybizAVZUBwBVUYnJyY9Uva61q4n9dHkG8of7gbCZda5fAmKRM3UAy
         gF0wVe9AFurlN9Tu1Rt6eJJBqCvT/o05auLh2bDVMmuuZE0hRMqz5JOYVg05yxyo3h9X
         YC1xGAop6rNgiydpgWLUTqMIr6XTujTxJ1BjbfuMeCCD10dDN7G2enp1uda36Na1YhPH
         W41Y9FCB7d2LMW9t1XffrsZ9w8P/pWqT1WcNWU8jLH77r7gFT9V3WxYpK9ijQA6bMBLF
         u0fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/7RI36/NO7iUF04dhVnObW1esIBKN8FF+iR/UuS6/jU=;
        b=yyNffUGBxi0pAxdkP2wH7Jmycqebz84QsyGaMhYzR6lIXNQPnpRFM5PXKgKmljfGUs
         F6cfIuD/N/xOKjFgw4RVWeS8W0x7Lu3Sqd32L0/PRR+KQrY+DPyGi1msO2LUmHJamqpN
         I/hhqUgIbheUifEsfLMcB0xmwNuMJ8SRzkPRptJnBIVs/YXYw+dzPFdBoPL2y2me/2Lt
         vRbMbwQIiISxZbfycLhWG+AA/N22tNu8FTE7ShJQ/77YvvkuxX6eN9IlgCUreCK2N4rS
         5WdvjGuJuxS3qeid3+Qq0ZyfXYEKvuwwjFJqv298mMjeiCGYwJ49INdOpGBSurUKDW/y
         gZ6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Da5fgDtG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/7RI36/NO7iUF04dhVnObW1esIBKN8FF+iR/UuS6/jU=;
        b=qGgHW8wikjHjtzf0kuFTlxc1xTbqqwNDo96hU9g4t4ZY/WeaGuTkLSFqV5r46DD8oH
         EIZMXAYPnCxW0ATiRG7RZ1wpCNtFyjhUHA+IM/A0fOH/YqtSKIPJykVrEZtZ4OgLmkvz
         Cp7OYJvifRb2fYp5erfAEnunbVq22A+wjQzIfemiGtVfwkFHEI+mpO3615NsEs2FCNyV
         xy6yBARRZX4//JnUh4Ets4Yd/8UKUIEMOGpQOxtxlYovt97Kr6jNzaOFi8kE8I2wqj4D
         FT+J84PGkKRaGHcwlAgaj0IC1vtE7BsrldiRpqJuSNyTdwU29p4wA4IjOE7oXCa9ZQch
         Dpmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/7RI36/NO7iUF04dhVnObW1esIBKN8FF+iR/UuS6/jU=;
        b=5vKyuTjdbIuynJZkzdN+FbqcGiysPUSqD1gE0iMMLyo5L5WRZKzBDX22yCE3TEae76
         EBxWWQAXTop8h3BotPva+YA54GI0nWJyZkruzjoy2E+eN17fbRkKqmBaEFBpw4HxVstU
         CdlNSAbRJxc0LDFKhiTJJurXVpOfraO6GZy/J8T1SHeiycAtht9mBQ8GWbAZiIBaTPB1
         oq3gvceRrIbQR8nDyV2+qGkeDoeXAqSVGhLBSwvcd+lIT2dnB5/zJCnWUFMMmqb/KzRY
         iKOq/QPrHcaSwsCWeOupF0vxldoIEFk/ntNzAz2emuYbbv0k5VwHMQ0DYCFeAondiPz9
         LSWg==
X-Gm-Message-State: AOAM530s+y7i258dNAzeA58uEgEML8cJlctg81/djFe9F6lCd0MdQNlz
	zm67NIuJC34cS68kI4lISIs=
X-Google-Smtp-Source: ABdhPJyv2f3xiwGiAOCCgy7Fda6v/OPL+Tal4eOrgpNGh2rZo8LIXUHY1ws3kEVDTPs2S7BaQEbf8A==
X-Received: by 2002:aca:ea55:: with SMTP id i82mr922657oih.96.1637357529940;
        Fri, 19 Nov 2021 13:32:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:ac94:: with SMTP id v142ls369002oie.4.gmail; Fri, 19 Nov
 2021 13:32:09 -0800 (PST)
X-Received: by 2002:a05:6808:211f:: with SMTP id r31mr2830117oiw.64.1637357529521;
        Fri, 19 Nov 2021 13:32:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637357529; cv=none;
        d=google.com; s=arc-20160816;
        b=XhC51uXmKohUczkNgzDvJhhXd24ck4/lWnUKs4O56UPDAT+UcnmKkkQK0qYuf5+G3y
         jLQPs1LZbrOV4WB2p4M6cEMIhTJ2/PrHKDmD7cIGY0Z98A7kspgsJhhit3kBpOTvzs/9
         okNp1PLCXW+GPAhwF6RDlhv3Jn5pE+/eF27z113wUA+q65b5BlYL0sjTxidAfW4Ttc1v
         JRYio4F7F3T068tWZOjGKlpL8McTdzjdkYf76syBNUzZVhKuZbIUkIG0iCYFezRUwMZi
         V48lGXpFvhJJuwuvIAbHviXLI3vX4ytlk1LlMTkARwcAEUi9rh8WrAaMmYbhUadyH2Vj
         fMvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0GXHfM1zHpJu5wwWGSWsee6iiyt6MnGHGfBIxpmPLPk=;
        b=Ig8CJ3oQcfxYij5AJ1zsxQqG+qnp1ufzMwFvAQL5qnlZVxzu2bx3dVPmrhu6bJOR4G
         LTi5w5RzY9QNbH7HuXRTqRFfom01K+oNcM3iXakC6RDBqAVnBNFTdrXBLZj0JRnfbGWE
         aOgZomr/iAadN+McbrE9Vbtsi58UrV+RmFlgJm98FfpDKIGKaUT2cGM7vmXOoMPRGStR
         q85haKbDwSwknBBHgy1Dng8y6Tbixm6YzdvJuehFltBxKQAdOTbBkx1N7ZUCKkYM8MuX
         M7XgfgElz/0Q6mUnuZDxzSx2x83PyrnMrV4HmdZDwV3Sq2nwNlX5W46w7uBJbcK8j9v8
         5dsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Da5fgDtG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x232.google.com (mail-oi1-x232.google.com. [2607:f8b0:4864:20::232])
        by gmr-mx.google.com with ESMTPS id s16si95565oiw.4.2021.11.19.13.32.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Nov 2021 13:32:09 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) client-ip=2607:f8b0:4864:20::232;
Received: by mail-oi1-x232.google.com with SMTP id bf8so24221621oib.6
        for <kasan-dev@googlegroups.com>; Fri, 19 Nov 2021 13:32:09 -0800 (PST)
X-Received: by 2002:a05:6808:118c:: with SMTP id j12mr2759146oil.65.1637357529142;
 Fri, 19 Nov 2021 13:32:09 -0800 (PST)
MIME-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com> <20211118081027.3175699-24-elver@google.com>
 <20211119203135.clplwzh3hyo5xddg@treble>
In-Reply-To: <20211119203135.clplwzh3hyo5xddg@treble>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Nov 2021 22:31:57 +0100
Message-ID: <CANpmjNPG1OdL9i73jiGH3XNmR+q+fRJfCaGrUXefRYu1kqhOGw@mail.gmail.com>
Subject: Re: [PATCH v2 23/23] objtool, kcsan: Remove memory barrier
 instrumentation from noinstr
To: Josh Poimboeuf <jpoimboe@redhat.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Da5fgDtG;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, 19 Nov 2021 at 21:31, Josh Poimboeuf <jpoimboe@redhat.com> wrote:

> > +     if (insn->sec->noinstr && sym->removable_instr) {
> >               if (reloc) {
> >                       reloc->type = R_NONE;
> >                       elf_write_reloc(file->elf, reloc);
>
> I'd love to have a clearer name than 'removable_instr', though I'm
> having trouble coming up with something.
>
> 'profiling_func'?
>
> Profiling isn't really accurate but maybe it gets the point across.  I'm
> definitely open to other suggestions.

Well, this bit is not true for all "profiling functions" either. It's
only true for instrumentation functions that appear in 'noinstr' and
that the compiler can't remove on its own, but are valid to remove by
objtool in noinstr code, hence 'removable_instr'.

I'm really quite indifferent what we call it, so I'll leave you to
pick whatever sounds best:

-- profiling_func
-- nop_profiling_func
-- optional_profiling_func
-- noinstr_remove
-- removable_profiling_func
-- noinstr_nop_func
-- noinstr_nop
-- nop_in_noinstr
-- invalid_in_noinstr

?

> Also, the above code isn't very self-evident so there still needs to be
> a comment there, like:
>
>         /*
>          * Many compilers cannot disable KCOV or sanitizer calls with a
>          * function attribute so they need a little help, NOP out any
>          * such calls from noinstr text.
>          */
>

I'll add it.

> > +{
> > +     /*
> > +      * Many compilers cannot disable KCOV with a function attribute so they
> > +      * need a little help, NOP out any KCOV calls from noinstr text.
> > +      */
> > +     if (!strncmp(name, "__sanitizer_cov_", 16))
> > +             return true;
>
> A comment is good here, but the NOP-ing bit seems out of place.

I'll fix that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPG1OdL9i73jiGH3XNmR%2Bq%2BfRJfCaGrUXefRYu1kqhOGw%40mail.gmail.com.
