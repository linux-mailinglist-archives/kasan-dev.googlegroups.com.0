Return-Path: <kasan-dev+bncBDW2JDUY5AORB4PH3GYAMGQENPCCTFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id DF45289F069
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 13:11:46 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-41401f598cfsf38252415e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 04:11:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712747506; cv=pass;
        d=google.com; s=arc-20160816;
        b=kpVfYmkBWHsf4FMVGoWGqmasfKaXsX4DBiE8vDlV3aR5Bga0Z0bYML/6BAehc25gQ/
         6QsCITUq6dixfjLbnpKXY7yJd8xCqDaWz1YicNt1ad7SrtxNbgtPw7w6YataD7YClolu
         geCucriKdl68ut38BQAUE5961hShAIi44nlXc4vb+wnHJ8bTPxy780q+ZrgylBKvklFt
         KOWLnoiWFe4OvkFZ2tO3qGe05bG87zTkCSmGLE/OhiAxbgYwzhUbcK9+VJut8+B2hCK0
         ofFR3l5Ru22EstTKV5irWHU4OOHe7eoo0Pu5nmnKI6w8lOzZsCEJCmj6gdIBKSQm9znv
         TvMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=rqTCEqdr76JQFSt7rNcWALNGLt6Mcl14Hw4wrfvSBGM=;
        fh=1ZK6Mgo8W4JZDCUIFS+A71WE1bxITLccv8ygPgKNsSw=;
        b=cGFCJRdDpTxBlibiQ+XM0SwlpxR/D8gZSq9HKS+MYk4P9k0FGaq8j5L+2tFiR0jhr5
         3OtvCA/XwgaKLa7bL5tEhpCw/c86FudUHQ0iJ7p58TC5qA2/cRe1NipVetP4w440WQV6
         t+GfkIOzMwMYANT4fmcBYwKJHZmuMeGk4/w8zyvklBDGImrbJKBGB7UrvZa4VynMPwCA
         zBZ/ydcx1SF87n9wxe1UoGzkmEfgqTYiCefQWXu7echXDlcfK2jCfVM6LGcJkipPFsEt
         wW9y1pQAToHnH0cmES/UFtO7uTw+um4U6XocS5fx8E3F94Wx5Hkz1kYHcO3lcyNUA3yg
         QWxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=B0Nim2rs;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712747506; x=1713352306; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rqTCEqdr76JQFSt7rNcWALNGLt6Mcl14Hw4wrfvSBGM=;
        b=NkjXR8j46XHNvY4VTBzygX0U+lVFMB3nOAECOUlczlgzmeaxUeKW1/Y48qlZDFMOXl
         7kXIYrgWyx1owLwSyfGfNI3ggug+5kmIkuK+d5cJtsI830SOC9TiKQQqqlLKG7fpk6b5
         Wgdfg6oxCqZWwhBsQ+eUdkos+RoQIa3W7h+t/386GKEJVOIyEnWZiO9klRNPl9WBH4WE
         ccArhylq6+uvzmUeeanF5ryjGS4ZmD+nu181NPCFaXmN5hLxBToqj+cWNEtUfBGtdsV+
         EILy0NOuLmpxa4kswq0HBraD1mBOfiLhMZG18l8DMJq+CUFwBvQLqMttTOFYJGFe0uG2
         wZLw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1712747506; x=1713352306; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rqTCEqdr76JQFSt7rNcWALNGLt6Mcl14Hw4wrfvSBGM=;
        b=N8eaiCTXgmth1kPn9YpBPUxoe70XOdrLoyMn+44IfV0kqSE25tGf4rUgzTEyttnqtG
         MOQUPefO/S5zBQua1Ar301UT9Icozs4x1oWt8zNfNxc9D1YIpCtL7lXqtz9YQe21mCsI
         oyNQOQ/QMA5D35J9kCtQgVJNmH+yK673h0ZCr0LZmj18X1do6X60uBR8ySmsvbzSZcGL
         DJG5PTsSu08L4jUVcjPP5WXHG4pfCHPbOZQQ421zunDNOVxKJWuE3lB2u/S+B5RhXVrc
         PZDR1uvCrVb/vHb9KF8y7rJKYCeiipyjEBkzW3qcJ1M6OS+oiss4onF5Rz5Q8DYpVJfu
         nFOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712747506; x=1713352306;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rqTCEqdr76JQFSt7rNcWALNGLt6Mcl14Hw4wrfvSBGM=;
        b=Na49xc0E5GofTwtFzozy/GyCZm5YiJLn7h3ihnp8y8b7Sraw2jUjowL1QNzpXbLNyP
         OCj90l1hQcWLfv6FFoGO/Z1LorFXOHaqNhon7q9Myz1tOaLmepGVK2AfC4B2w6O7Pqnx
         ezs6K7XdvPVQzOt882d6hWKA/TcA0LDg0/zpWqjcc20JswcjLd/H3YakXXl+sFBNDF0W
         xXf2voDOWEihqLNmK+NbZ6k6nMbH6yeCqrPy3XCrtjgQ3NhTtXadnTTR+UDF4fLnzno7
         nGm5byZJ/QYcSz8lNfxtQqOst4hAtjVGWe2n9T+WorcOhw3bgDQH35GAAHCaonzSdkIu
         Z8Dw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUlzwzIuc0KgwNTsAiDU1HSS6gzCCZOyqMmbMguLjdxhy12Otz/Jm6LmUBWSd5fkbnlrsJ53uIJc4LeSCaxfrYjnipfe5BU5g==
X-Gm-Message-State: AOJu0YzjkVh4lTZ/Gtl0d8O7kNpM3xbpDwSkAWM53qcWIad0OVv5sPQ6
	1dNdIbV6wHUpRADGpk3Fj3m7D5cZLc7lQkHrGyhKtciBekdvaqJt
X-Google-Smtp-Source: AGHT+IHhFI3o5DxX1M1k3eXnfL3u2GAnQYNORsqPck2vZS+8506RL5PFxzX+4IDROmXqzfzkEFNAWw==
X-Received: by 2002:a05:600c:1c01:b0:417:be50:8e5e with SMTP id j1-20020a05600c1c0100b00417be508e5emr517377wms.26.1712747505625;
        Wed, 10 Apr 2024 04:11:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b02:b0:416:b4c9:db2a with SMTP id
 m2-20020a05600c3b0200b00416b4c9db2als610306wms.2.-pod-prod-06-eu; Wed, 10 Apr
 2024 04:11:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXIw6CmlZXrl4aBbmlDy6P/J9HohCK8XezdVp+8Al5GTsslkpsikpTDsgknEt5SUHvke8B7IDKUmwKwX7mWNEdS5SMwsSuycLMxdA==
X-Received: by 2002:a7b:c84a:0:b0:416:9ba0:8f17 with SMTP id c10-20020a7bc84a000000b004169ba08f17mr1542204wml.22.1712747503757;
        Wed, 10 Apr 2024 04:11:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712747503; cv=none;
        d=google.com; s=arc-20160816;
        b=h9FD3B2v0yLwGlHeH7/2fxKdP7js0nec9+k+ppiNeJJNFSPdg0EBNUUom9oNnNyWY7
         /FG2IYL88rOdzjQ3vkawlAdd1eQwVgFF+j+BblpZio+8OMP6gPJ92c1CGAQzC6/0A1Pr
         c12M8C2XEWt0KdLnvat3g64lyz58awaRoHWMsQvXL5Zm+Ie+U8/+lnwR5aykTB1Jn4L6
         XCdjk/KFe9BOiHugqrYlCYNdrEOI58rzI8MKzrNmI+TvTdXTk76OMm4NrsWk2iwwSCLa
         JrrS65WiLIif65AutUKcNTLYWh340kVyk+g5aDWDh1jXuW2LV46bBuOKRiYKi+Nrwlt2
         csVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=PjOzONbMlmADmG3XYm7p48IJrLzQYuZRD5b8PRoWYhU=;
        fh=G9bNwfWNGeV0NMsujVwHmyhZmfklqIRQ28lrv5T6g98=;
        b=d03aTrkRRkfKLdO02l7doURnqraAISyE4kuir5GmGVqtexndj4OK5uHbvO/y2pzniC
         CgabZ4qytlBOu7OLj4XE2BrUg50Tue7/iLcZV+KuUDHCoJ6ZfTUUWL4FEy+CjI1+4zaN
         z0Vm/d81Mdi8iMbptEcqW7Jev4W3D9sojoWYRNNRNcToXu7WUec7KFiFPd98NeLB4/aB
         JlMUy7ah55yOTXbYn8CLMYoAWwPNEeiVmKG10j+nP82Fa4RYLVhS07Bafe/iZPNVrtkf
         Y6Gf2Xdw0LWiACNA/9BqKGpMkM0755wTAcZZK1nTunopdqvaHDoG+r9YDSpa7jLH172M
         eNtw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=B0Nim2rs;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id t6-20020a05600c328600b00417bd5d5484si58711wmp.1.2024.04.10.04.11.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Apr 2024 04:11:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-346406a5fb9so1013885f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 10 Apr 2024 04:11:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWxyCHQcU5eh80JzDaUcrjSaPlnXIvlnXDetLSXDY48ysd4OHxGycDixte+NEHx4JNDD0QL/DMSVvp7jXtF23CtUz5gg8OHCXfACA==
X-Received: by 2002:a5d:58f6:0:b0:343:70cc:dedf with SMTP id
 f22-20020a5d58f6000000b0034370ccdedfmr1666476wrd.20.1712747503233; Wed, 10
 Apr 2024 04:11:43 -0700 (PDT)
MIME-Version: 1.0
References: <20231004145137.86537-1-ubizjak@gmail.com> <20231004145137.86537-5-ubizjak@gmail.com>
 <CAHk-=wgepFm=jGodFQYPAaEvcBhR3-f_h1BLBYiVQsutCwCnUQ@mail.gmail.com>
 <CAFULd4YWjxoSTyCtMN0OzKgHtshMQOuMH1Z0n_OaWKVnUjy2iA@mail.gmail.com>
 <CAHk-=whq=+LNHmsde8LaF4pdvKxqKt5GxW+Tq+U35_aDcV0ADg@mail.gmail.com>
 <CAHk-=wi6U-O1wdPOESuCE6QO2OaPu0hEzaig0uDOU4L5CREhug@mail.gmail.com>
 <CAFULd4Z3C771u8Y==8h6hi=mhGmy=7RJRAEBGfNZ0SmynxF41g@mail.gmail.com>
 <ZSPm6Z/lTK1ZlO8m@gmail.com> <CAFULd4Z=S+GyvtWCpQi=_mkkYvj8xb_m0b0t1exDe5NPyAHyAA@mail.gmail.com>
In-Reply-To: <CAFULd4Z=S+GyvtWCpQi=_mkkYvj8xb_m0b0t1exDe5NPyAHyAA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 10 Apr 2024 13:11:32 +0200
Message-ID: <CA+fCnZen+5XC4LFYuzhdAjSjY_Jh0Yk=KYXxcYxkMDNj3kY9kA@mail.gmail.com>
Subject: Re: [PATCH 4/4] x86/percpu: Use C for percpu read/write accessors
To: Uros Bizjak <ubizjak@gmail.com>
Cc: Ingo Molnar <mingo@kernel.org>, Linus Torvalds <torvalds@linux-foundation.org>, x86@kernel.org, 
	linux-kernel@vger.kernel.org, Andy Lutomirski <luto@kernel.org>, 
	Nadav Amit <namit@vmware.com>, Brian Gerst <brgerst@gmail.com>, 
	Denys Vlasenko <dvlasenk@redhat.com>, "H . Peter Anvin" <hpa@zytor.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Borislav Petkov <bp@alien8.de>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=B0Nim2rs;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436
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

On Mon, Oct 9, 2023 at 4:35=E2=80=AFPM Uros Bizjak <ubizjak@gmail.com> wrot=
e:
>
> On Mon, Oct 9, 2023 at 1:41=E2=80=AFPM Ingo Molnar <mingo@kernel.org> wro=
te:
> >
> >
> > * Uros Bizjak <ubizjak@gmail.com> wrote:
> >
> > > diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> > > index ecb256954351..1edf4a5b93ca 100644
> > > --- a/arch/x86/Kconfig
> > > +++ b/arch/x86/Kconfig
> > > @@ -2393,7 +2393,7 @@ config CC_HAS_NAMED_AS
> > >
> > >  config USE_X86_SEG_SUPPORT
> > >       def_bool y
> > > -     depends on CC_HAS_NAMED_AS && SMP
> > > +     depends on CC_HAS_NAMED_AS && SMP && !KASAN
> > > +     depends on CC_HAS_NAMED_AS && SMP && !KASAN
> >
> > So I'd rather express this as a Kconfig quirk line, and explain each qu=
irk.
> >
> > Something like:
> >
> >         depends on CC_HAS_NAMED_AS
> >         depends on SMP
> >         #
> >         # -fsanitize=3Dkernel-address (KASAN) is at the moment incompat=
ible
> >         # with named address spaces - see GCC bug #12345.
> >         #
> >         depends on !KASAN
>
> This is now PR sanitizer/111736 [1], but perhaps KASAN people [CC'd]
> also want to be notified about this problem.
>
> [1] https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D111736

Filed a KASAN bug to track this:
https://bugzilla.kernel.org/show_bug.cgi?id=3D218703

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZen%2B5XC4LFYuzhdAjSjY_Jh0Yk%3DKYXxcYxkMDNj3kY9kA%40mail.=
gmail.com.
