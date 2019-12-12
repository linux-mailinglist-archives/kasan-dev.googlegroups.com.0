Return-Path: <kasan-dev+bncBCRY3K6ZWAFRBDE6ZDXQKGQESICQNZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 357F211C9FC
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 10:57:34 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id l21sf389951ota.3
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 01:57:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576144653; cv=pass;
        d=google.com; s=arc-20160816;
        b=fmfesfOeaaBIy/prLgG7Vprz3VQEhP79ZKB/CviRvKbbmQzpP1LCSF9nMdLgM/eNOV
         WsIlI8ua7ByKCphqZeP9QGazQftTRvyTqJ+BUJVh7iBH1xlfcGgFgnGvqJMGHKL257Uo
         TsbpxyTaladZYKIVJSKZ+pO5XA7NsfxClmRUpyMj083Owus6iXUsLYUp0Ut2C9iOmY4n
         ObO3tOYfNqrq5+F5zhh5m2v94BrrK5fwqZjbgdEwJNZNNASmBiNksvb/jIppyoi4kixW
         PyyUp5y7AK+3m9ZfYbLembGGre79RJFNsVhWOuPWwKPMz/mWxtoyivObnAyEEXelfKTP
         kdCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=klrpADLBC1fcuTtf+RS8YNxd2eCOHRkd1SFK74JCMqs=;
        b=S/OEKFx7r1fYd1NTg6XzJmVNNa7/oZej9OjB1uoShURCuOEkIAP3HDHQXTbiPQFeWV
         FiyLuzRou51YLvl6oM1BN5JopsHH8UIQIjDxkcgTNa0F7a1+HE4d669oMt0+ZlSGU1o0
         Y4nRGXJRR0xRF4oJg4iGtpEiM60QSVjlcTrTs6kkcwSECZMGGracFKsWyVePf+7EwOtM
         5LaN271mlAqNG2zYaGL4z1b2O4GZOHYEYQj6Jo6LAW+2UYoZvM06tQqFzW9JGwkSJsxY
         eOHHbi32tnYBkiiuFUMvBF1Fnuqt4Ss85EO7Dp0e8XEDt+yvaw9aCEg+uGjI2bBDs+25
         ng/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=XadX32YS;
       spf=pass (google.com: domain of truhuan@gmail.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=truhuan@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=klrpADLBC1fcuTtf+RS8YNxd2eCOHRkd1SFK74JCMqs=;
        b=b3O/dS3Fvac2lOsCj57+toyCvqJ6VRbsOcKlOUlEl8GTKPWfZO+0yHOWeMh5HZWAoC
         NQiy9TNCCSI0aYmJyHj4QUI55PHFYfImSulktL8QBGmqTVTsU9MjGYwxShQ31lqRR85B
         JG4R10XJ6ZKOFVbg8VCRvh9S0tO/NyKmbU+/V6w/pnbXaq0h14HW3txY5ko/1sQyCzeZ
         ZoQcWtKj6BFxxGWHL38xTvVFrm7+onY2ClWjG5FfQPFjxCLWkM28xJdH+CVdScZVb+Yp
         7bL0cNSRS2RX+riCCeTnqTm1+nskUcIVuu2ikLpEEA/QNDcfTH3EgiCENSEJK+0PEuR1
         Y7Sg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=klrpADLBC1fcuTtf+RS8YNxd2eCOHRkd1SFK74JCMqs=;
        b=qpbWRcOAsKX2Y/xF+cXn79tHwzV5Vx+OLGI/uE946ifeRtqoNTvVbpnlcYWMnmelXP
         lNwcSctrRZ1heHwFQl8eQTfG4Qwl0tclb2UlX/AwpZLvnMQ4x7/zZ2SRZtuWfS7lQ4vk
         oNjXAC3C0JpvLdqY3kkAlK4lstBy91dy8nAHkE8cqQKosablOYOMQQ8YJhhdFuBTAp7L
         tQxhtJElUzOXKGhasJEllLvvA797W/CquSAgCmOY5qZ87KViU+UAmj5QdKRoL3id866G
         gKi/MxseoLKTmtueKg62H2W4Kf9nRKzXRoccO+mLbH93h6Aom5Z51TxbIEOt+Vvi5OQD
         C4BA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=klrpADLBC1fcuTtf+RS8YNxd2eCOHRkd1SFK74JCMqs=;
        b=DiBEIps+DzsyVxFLY/96uAOlHs4dJHB8Mmcj6cLzm0F6GMZVIGqhcH5uaumfTSjZF/
         ySE2FpUUKDstt8pABJIP7/mB6pTI48e4ecCLXHqRmbs5joQBRJDbJ+BXXHvXqK5eLFj8
         Sz2tOPDWWSaChOLIEswZXXCuc3ZOEzVSfVLPxZRrJ6WLOnNL8ZCTUIQqAI/wk5tRXuc2
         9Q3nZ9vn/RBnOxBBenre0f/KdeX9k41ShMo+SREYbSrU5/ScJ8O19eHkDX3zAH8qPkMZ
         79wXrdHxsgX+t/qwq4ipPksqJlfBRyGsP4qfoSkHKwDZsDNr1IKvYfHzzdlUJX/woaWt
         40tw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV8ArGY+EAy6pi9xwZhMv55rPpadBKxqNov9XfCeCLCbTWD6t+a
	nu07lAs3MEIz0OCgdGoDltA=
X-Google-Smtp-Source: APXvYqx72bEFBK5GDdyOAayPmQQvDvKQ8ceZaPFum7uP6Rl1cIAkQD+matzLFUiYKN1mnYCUsuaTSA==
X-Received: by 2002:a05:6830:1257:: with SMTP id s23mr7210045otp.241.1576144653043;
        Thu, 12 Dec 2019 01:57:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7dd6:: with SMTP id k22ls1182880otn.5.gmail; Thu, 12 Dec
 2019 01:57:32 -0800 (PST)
X-Received: by 2002:a9d:6f0a:: with SMTP id n10mr7533483otq.54.1576144652644;
        Thu, 12 Dec 2019 01:57:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576144652; cv=none;
        d=google.com; s=arc-20160816;
        b=T52fKTbeZgRRR9O2OgZT5WUm1EkSzRJeKQUDBs+Hy3BHtHL+Tl+erbKww24W2MhmaK
         EFJ7tXr1fJRAdatUvMtWXQiahvo7t/zkosqCg6ZG61eEYQt7mqm7T3PJP9nQjyqKDND6
         9Smd0yEUpkaoskqy331P8FQGcl3U2y3O057qWyya6T3+2ybW1TUaSTTohj/0koPV05x7
         F4VnBUTY4hwnqetLO/vrPgZd5F8i9gS1M9uMFcEC9SymNhgX+blvRA+ipQ+c4g4NVqBw
         MLlGi5hnHh6y7Ly3CENIVTrfLGYt/2YEvapqcTYJnPDxYml/x7BqtLHKkbxOeD6tfqyQ
         qVxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DKtmvJjHV6rjixBBkVKsl/uBAIg8pzOxUUpYe/QIt/w=;
        b=XD1k3QohquYSDZH5cEDbTTGqu/R5UGZT/+9kAmW32ILaVi2nGB6f3X/N1gk+vl+F4K
         uk4F4fZH+ArOwMWYNkrqbjBv8x+fGXGFfulaHqdgyEeuY+cHtmeE3NewL7RAqXzbxy/f
         fDDJJrhoUNXnQG2hoeqadj+KtFusJrC9V1fRDdNgpeG3N7dapV6cvGgxJ8M2Bi7mHaR8
         IPlhQeveRYfCrQIg1owBXfSKl6o80eOHbgVZ2HFaZ6Q3XbuKmLKz7Kh/QYJzsLz3ks/R
         MM6fh5RF4C4VeIU+qucXUxehNEbnYeeXHBEFxnme3DpODlMU4mAj/mlPgpd09wFfA112
         mrmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=XadX32YS;
       spf=pass (google.com: domain of truhuan@gmail.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=truhuan@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x730.google.com (mail-qk1-x730.google.com. [2607:f8b0:4864:20::730])
        by gmr-mx.google.com with ESMTPS id 13si232290oin.1.2019.12.12.01.57.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Dec 2019 01:57:32 -0800 (PST)
Received-SPF: pass (google.com: domain of truhuan@gmail.com designates 2607:f8b0:4864:20::730 as permitted sender) client-ip=2607:f8b0:4864:20::730;
Received: by mail-qk1-x730.google.com with SMTP id d202so1125187qkb.1
        for <kasan-dev@googlegroups.com>; Thu, 12 Dec 2019 01:57:32 -0800 (PST)
X-Received: by 2002:a37:6cc1:: with SMTP id h184mr7188433qkc.96.1576144652145;
 Thu, 12 Dec 2019 01:57:32 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
In-Reply-To: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
From: Walter <truhuan@gmail.com>
Date: Thu, 12 Dec 2019 17:58:12 +0800
Message-ID: <CADyx2V6j+do+CmmSYEUr0iP7TUWD7xHLP2ZJPrqB1Y+QEAwzhw@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, paulmck@linux.ibm.com, Paul Turner <pjt@google.com>, 
	Daniel Axtens <dja@axtens.net>, Anatol Pomazau <anatol@google.com>, Will Deacon <willdeacon@google.com>, 
	Andrea Parri <parri.andrea@gmail.com>, stern@rowland.harvard.edu, akiyks@gmail.com, 
	npiggin@gmail.com, boqun.feng@gmail.com, dlustig@nvidia.com, 
	j.alglave@ucl.ac.uk, luc.maranget@inria.fr
Content-Type: multipart/alternative; boundary="0000000000001b1ab405997ec622"
X-Original-Sender: truhuan@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=XadX32YS;       spf=pass
 (google.com: domain of truhuan@gmail.com designates 2607:f8b0:4864:20::730 as
 permitted sender) smtp.mailfrom=truhuan@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--0000000000001b1ab405997ec622
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi Marco,

Data racing issues always bothers us, we are happy to use this debug tool t=
o
detect the root cause. So, we need to understand this tool implementation,
we try to trace your code and have some questions, would you take the free
time
to answer the question.
Thanks.

Question:
We assume they access the same variable when use read() and write()
Below two Scenario are false negative?

=3D=3D=3D
Scenario 1:

CPU 0:
                CPU 1:
tsan_read()
              tsan_write()
  check_access()
              check_access()
     watchpoint=3Dfind_watchpoint() // watchpoint=3DNULL
watchpoint=3Dfind_watchpoint() // watchpoint=3DNULL
     kcsan_setup_watchpoint()
           kcsan_setup_watchpoint()
        watchpoint =3D insert_watchpoint
               watchpoint =3D insert_watchpoint
        if (!remove_watchpoint(watchpoint)) // no enter, no report
  if (!remove_watchpoint(watchpoint)) // no enter, no report

=3D=3D=3D
Scenario 2:

CPU 0:
               CPU 1:
tsan_read()
  check_access()
    watchpoint=3Dfind_watchpoint() // watchpoint=3DNULL
    kcsan_setup_watchpoint()
      watchpoint =3D insert_watchpoint()

tsan_read()
             tsan_write()
  check_access()
             check_access()
    find_watchpoint()
      if(expect_write && !is_write)
        continue
      return NULL

    kcsan_setup_watchpoint()
      watchpoint =3D insert_watchpoint()

      remove_watchpoint(watchpoint)
        watchpoint =3D INVALID_WATCHPOINT


                          watchpoint =3D find_watchpoint()


                          kcsan_found_watchpoint()

                              consumed =3D try_consume_watchpoint() //
consumed=3Dfalse, no report

Thanks.
Walter

'Marco Elver' via kasan-dev <kasan-dev@googlegroups.com> =E6=96=BC 2019=E5=
=B9=B49=E6=9C=8820=E6=97=A5 =E9=80=B1=E4=BA=94
=E4=B8=8B=E5=8D=8810:19=E5=AF=AB=E9=81=93=EF=BC=9A

> Hi all,
>
> We would like to share a new data-race detector for the Linux kernel:
> Kernel Concurrency Sanitizer (KCSAN) --
> https://github.com/google/ktsan/wiki/KCSAN  (Details:
>
> https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.=
rst
> )
>
> To those of you who we mentioned at LPC that we're working on a
> watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> renamed it to KCSAN to avoid confusion with KTSAN).
> [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
>
> In the coming weeks we're planning to:
> * Set up a syzkaller instance.
> * Share the dashboard so that you can see the races that are found.
> * Attempt to send fixes for some races upstream (if you find that the
> kcsan-with-fixes branch contains an important fix, please feel free to
> point it out and we'll prioritize that).
>
> There are a few open questions:
> * The big one: most of the reported races are due to unmarked
> accesses; prioritization or pruning of races to focus initial efforts
> to fix races might be required. Comments on how best to proceed are
> welcome. We're aware that these are issues that have recently received
> attention in the context of the LKMM
> (https://lwn.net/Articles/793253/).
> * How/when to upstream KCSAN?
>
> Feel free to test and send feedback.
>
> Thanks,
> -- Marco
>
> --
> You received this message because you are subscribed to the Google Groups
> "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an
> email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/CANpmjNPJ_bHjfLZCAPV23AXFfiPi=
yXXqqu72n6TgWzb2Gnu1eA%40mail.gmail.com
> .
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CADyx2V6j%2Bdo%2BCmmSYEUr0iP7TUWD7xHLP2ZJPrqB1Y%2BQEAwzhw%40mail.=
gmail.com.

--0000000000001b1ab405997ec622
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

PGRpdiBkaXI9Imx0ciI+SGkgTWFyY28sPGJyPjxicj5EYXRhIHJhY2luZyBpc3N1ZXMgYWx3YXlz
IGJvdGhlcnMgdXMsIHdlIGFyZSBoYXBweSB0byB1c2UgdGhpcyBkZWJ1ZyB0b29sIHRvPGJyPmRl
dGVjdCB0aGUgcm9vdCBjYXVzZS4gU28sIHdlIG5lZWQgdG8gdW5kZXJzdGFuZCB0aGlzIHRvb2wg
aW1wbGVtZW50YXRpb24sPGJyPndlIHRyeSB0byB0cmFjZSB5b3VyIGNvZGUgYW5kIGhhdmUgc29t
ZSBxdWVzdGlvbnMsIHdvdWxkIHlvdSB0YWtlIHRoZSBmcmVlIHRpbWU8YnI+dG8gYW5zd2VyIHRo
ZSBxdWVzdGlvbi4gPGJyPlRoYW5rcy48YnI+PGJyPlF1ZXN0aW9uOjxicj5XZSBhc3N1bWUgdGhl
eSBhY2Nlc3MgdGhlIHNhbWUgdmFyaWFibGUgd2hlbiB1c2UgcmVhZCgpIGFuZCB3cml0ZSgpPGJy
PkJlbG93IHR3byBTY2VuYXJpbyBhcmUgZmFsc2UgbmVnYXRpdmU/PGJyPjxicj49PT08YnI+U2Nl
bmFyaW8gMTo8YnI+PGJyPkNQVSAwOiDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCBDUFUgMTo8YnI+dHNhbl9yZWFkKCkg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgdHNhbl93cml0ZSgpPGJyPsKgIGNoZWNrX2FjY2VzcygpIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIGNoZWNrX2FjY2VzcygpPGJyPsKgIMKgIMKg
d2F0Y2hwb2ludD1maW5kX3dhdGNocG9pbnQoKSAvLyB3YXRjaHBvaW50PU5VTEwgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgd2F0Y2hwb2ludD1maW5kX3dhdGNocG9pbnQoKSAvLyB3YXRj
aHBvaW50PU5VTEw8YnI+wqAgwqAgwqBrY3Nhbl9zZXR1cF93YXRjaHBvaW50KCkgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqBrY3Nhbl9zZXR1cF93YXRjaHBvaW50KCk8YnI+wqAgwqAgwqAg
wqAgd2F0Y2hwb2ludCA9IGluc2VydF93YXRjaHBvaW50IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgd2F0
Y2hwb2ludCA9IGluc2VydF93YXRjaHBvaW50PGJyPsKgIMKgIMKgIMKgIGlmICghcmVtb3ZlX3dh
dGNocG9pbnQod2F0Y2hwb2ludCkpIC8vIG5vIGVudGVyLCBubyByZXBvcnQgwqAgwqAgwqAgwqAg
wqAgaWYgKCFyZW1vdmVfd2F0Y2hwb2ludCh3YXRjaHBvaW50KSkgLy8gbm8gZW50ZXIsIG5vIHJl
cG9ydDxicj48YnI+PT09PGJyPlNjZW5hcmlvIDI6PGJyPjxicj5DUFUgMDogwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqBD
UFUgMTo8YnI+dHNhbl9yZWFkKCk8YnI+wqAgY2hlY2tfYWNjZXNzKCk8YnI+wqAgwqAgd2F0Y2hw
b2ludD1maW5kX3dhdGNocG9pbnQoKSAvLyB3YXRjaHBvaW50PU5VTEw8YnI+wqAgwqAga2NzYW5f
c2V0dXBfd2F0Y2hwb2ludCgpPGJyPsKgIMKgIMKgIHdhdGNocG9pbnQgPSBpbnNlcnRfd2F0Y2hw
b2ludCgpIDxicj48YnI+dHNhbl9yZWFkKCkgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqB0c2FuX3dyaXRlKCkgwqA8YnI+wqAgY2hlY2tf
YWNjZXNzKCkgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqBjaGVja19hY2Nlc3MoKTxicj7CoCDCoCBmaW5kX3dhdGNocG9pbnQoKSDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCA8YnI+
wqAgwqAgwqAgaWYoZXhwZWN0X3dyaXRlICZhbXA7JmFtcDsgIWlzX3dyaXRlKTxicj7CoCDCoCDC
oCDCoCBjb250aW51ZTxicj7CoCDCoCDCoCByZXR1cm4gTlVMTCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoDxicj7CoCDCoCBrY3Nhbl9zZXR1cF93YXRjaHBvaW50KCk8YnI+wqAgwqAg
wqAgd2F0Y2hwb2ludCA9IGluc2VydF93YXRjaHBvaW50KCkgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgPGJyPsKgIMKg
IMKgIHJlbW92ZV93YXRjaHBvaW50KHdhdGNocG9pbnQpPGJyPsKgIMKgIMKgIMKgIHdhdGNocG9p
bnQgPSBJTlZBTElEX1dBVENIUE9JTlQgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqA8YnI+wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgd2F0Y2hwb2lu
dCA9IGZpbmRfd2F0Y2hwb2ludCgpIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgPGJyPsKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIGtjc2FuX2ZvdW5kX3dhdGNocG9pbnQoKTxicj7CoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCBjb25zdW1lZCA9IHRyeV9jb25z
dW1lX3dhdGNocG9pbnQoKSAvLyBjb25zdW1lZD1mYWxzZSwgbm8gcmVwb3J0PGJyPjxicj5UaGFu
a3MuPGJyPldhbHRlcjxicj48L2Rpdj48YnI+PGRpdiBjbGFzcz0iZ21haWxfcXVvdGUiPjxkaXYg
ZGlyPSJsdHIiIGNsYXNzPSJnbWFpbF9hdHRyIj4mIzM5O01hcmNvIEVsdmVyJiMzOTsgdmlhIGth
c2FuLWRldiAmbHQ7PGEgaHJlZj0ibWFpbHRvOmthc2FuLWRldkBnb29nbGVncm91cHMuY29tIj5r
YXNhbi1kZXZAZ29vZ2xlZ3JvdXBzLmNvbTwvYT4mZ3Q7IOaWvCAyMDE55bm0OeaciDIw5pelIOmA
seS6lCDkuIvljYgxMDoxOeWvq+mBk++8mjxicj48L2Rpdj48YmxvY2txdW90ZSBjbGFzcz0iZ21h
aWxfcXVvdGUiIHN0eWxlPSJtYXJnaW46MHB4IDBweCAwcHggMC44ZXg7Ym9yZGVyLWxlZnQ6MXB4
IHNvbGlkIHJnYigyMDQsMjA0LDIwNCk7cGFkZGluZy1sZWZ0OjFleCI+SGkgYWxsLDxicj4NCjxi
cj4NCldlIHdvdWxkIGxpa2UgdG8gc2hhcmUgYSBuZXcgZGF0YS1yYWNlIGRldGVjdG9yIGZvciB0
aGUgTGludXgga2VybmVsOjxicj4NCktlcm5lbCBDb25jdXJyZW5jeSBTYW5pdGl6ZXIgKEtDU0FO
KSAtLTxicj4NCjxhIGhyZWY9Imh0dHBzOi8vZ2l0aHViLmNvbS9nb29nbGUva3RzYW4vd2lraS9L
Q1NBTiIgcmVsPSJub3JlZmVycmVyIiB0YXJnZXQ9Il9ibGFuayI+aHR0cHM6Ly9naXRodWIuY29t
L2dvb2dsZS9rdHNhbi93aWtpL0tDU0FOPC9hPsKgIChEZXRhaWxzOjxicj4NCjxhIGhyZWY9Imh0
dHBzOi8vZ2l0aHViLmNvbS9nb29nbGUva3RzYW4vYmxvYi9rY3Nhbi9Eb2N1bWVudGF0aW9uL2Rl
di10b29scy9rY3Nhbi5yc3QiIHJlbD0ibm9yZWZlcnJlciIgdGFyZ2V0PSJfYmxhbmsiPmh0dHBz
Oi8vZ2l0aHViLmNvbS9nb29nbGUva3RzYW4vYmxvYi9rY3Nhbi9Eb2N1bWVudGF0aW9uL2Rldi10
b29scy9rY3Nhbi5yc3Q8L2E+KTxicj4NCjxicj4NClRvIHRob3NlIG9mIHlvdSB3aG8gd2UgbWVu
dGlvbmVkIGF0IExQQyB0aGF0IHdlJiMzOTtyZSB3b3JraW5nIG9uIGE8YnI+DQp3YXRjaHBvaW50
LWJhc2VkIEtUU0FOIGluc3BpcmVkIGJ5IERhdGFDb2xsaWRlciBbMV0sIHRoaXMgaXMgaXQgKHdl
PGJyPg0KcmVuYW1lZCBpdCB0byBLQ1NBTiB0byBhdm9pZCBjb25mdXNpb24gd2l0aCBLVFNBTiku
PGJyPg0KWzFdIDxhIGhyZWY9Imh0dHA6Ly91c2VuaXgub3JnL2xlZ2FjeS9ldmVudHMvb3NkaTEw
L3RlY2gvZnVsbF9wYXBlcnMvRXJpY2tzb24ucGRmIiByZWw9Im5vcmVmZXJyZXIiIHRhcmdldD0i
X2JsYW5rIj5odHRwOi8vdXNlbml4Lm9yZy9sZWdhY3kvZXZlbnRzL29zZGkxMC90ZWNoL2Z1bGxf
cGFwZXJzL0VyaWNrc29uLnBkZjwvYT48YnI+DQo8YnI+DQpJbiB0aGUgY29taW5nIHdlZWtzIHdl
JiMzOTtyZSBwbGFubmluZyB0bzo8YnI+DQoqIFNldCB1cCBhIHN5emthbGxlciBpbnN0YW5jZS48
YnI+DQoqIFNoYXJlIHRoZSBkYXNoYm9hcmQgc28gdGhhdCB5b3UgY2FuIHNlZSB0aGUgcmFjZXMg
dGhhdCBhcmUgZm91bmQuPGJyPg0KKiBBdHRlbXB0IHRvIHNlbmQgZml4ZXMgZm9yIHNvbWUgcmFj
ZXMgdXBzdHJlYW0gKGlmIHlvdSBmaW5kIHRoYXQgdGhlPGJyPg0Ka2NzYW4td2l0aC1maXhlcyBi
cmFuY2ggY29udGFpbnMgYW4gaW1wb3J0YW50IGZpeCwgcGxlYXNlIGZlZWwgZnJlZSB0bzxicj4N
CnBvaW50IGl0IG91dCBhbmQgd2UmIzM5O2xsIHByaW9yaXRpemUgdGhhdCkuPGJyPg0KPGJyPg0K
VGhlcmUgYXJlIGEgZmV3IG9wZW4gcXVlc3Rpb25zOjxicj4NCiogVGhlIGJpZyBvbmU6IG1vc3Qg
b2YgdGhlIHJlcG9ydGVkIHJhY2VzIGFyZSBkdWUgdG8gdW5tYXJrZWQ8YnI+DQphY2Nlc3Nlczsg
cHJpb3JpdGl6YXRpb24gb3IgcHJ1bmluZyBvZiByYWNlcyB0byBmb2N1cyBpbml0aWFsIGVmZm9y
dHM8YnI+DQp0byBmaXggcmFjZXMgbWlnaHQgYmUgcmVxdWlyZWQuIENvbW1lbnRzIG9uIGhvdyBi
ZXN0IHRvIHByb2NlZWQgYXJlPGJyPg0Kd2VsY29tZS4gV2UmIzM5O3JlIGF3YXJlIHRoYXQgdGhl
c2UgYXJlIGlzc3VlcyB0aGF0IGhhdmUgcmVjZW50bHkgcmVjZWl2ZWQ8YnI+DQphdHRlbnRpb24g
aW4gdGhlIGNvbnRleHQgb2YgdGhlIExLTU08YnI+DQooPGEgaHJlZj0iaHR0cHM6Ly9sd24ubmV0
L0FydGljbGVzLzc5MzI1My8iIHJlbD0ibm9yZWZlcnJlciIgdGFyZ2V0PSJfYmxhbmsiPmh0dHBz
Oi8vbHduLm5ldC9BcnRpY2xlcy83OTMyNTMvPC9hPikuPGJyPg0KKiBIb3cvd2hlbiB0byB1cHN0
cmVhbSBLQ1NBTj88YnI+DQo8YnI+DQpGZWVsIGZyZWUgdG8gdGVzdCBhbmQgc2VuZCBmZWVkYmFj
ay48YnI+DQo8YnI+DQpUaGFua3MsPGJyPg0KLS0gTWFyY288YnI+DQo8YnI+DQotLSA8YnI+DQpZ
b3UgcmVjZWl2ZWQgdGhpcyBtZXNzYWdlIGJlY2F1c2UgeW91IGFyZSBzdWJzY3JpYmVkIHRvIHRo
ZSBHb29nbGUgR3JvdXBzICZxdW90O2thc2FuLWRldiZxdW90OyBncm91cC48YnI+DQpUbyB1bnN1
YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0
LCBzZW5kIGFuIGVtYWlsIHRvIDxhIGhyZWY9Im1haWx0bzprYXNhbi1kZXYlMkJ1bnN1YnNjcmli
ZUBnb29nbGVncm91cHMuY29tIiB0YXJnZXQ9Il9ibGFuayI+a2FzYW4tZGV2K3Vuc3Vic2NyaWJl
QGdvb2dsZWdyb3Vwcy5jb208L2E+Ljxicj4NClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIG9uIHRo
ZSB3ZWIgdmlzaXQgPGEgaHJlZj0iaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2th
c2FuLWRldi9DQU5wbWpOUEpfYkhqZkxaQ0FQVjIzQVhGZmlQaXlYWHFxdTcybjZUZ1d6YjJHbnUx
ZUElNDBtYWlsLmdtYWlsLmNvbSIgcmVsPSJub3JlZmVycmVyIiB0YXJnZXQ9Il9ibGFuayI+aHR0
cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi9DQU5wbWpOUEpfYkhqZkxa
Q0FQVjIzQVhGZmlQaXlYWHFxdTcybjZUZ1d6YjJHbnUxZUElNDBtYWlsLmdtYWlsLmNvbTwvYT4u
PGJyPg0KPC9ibG9ja3F1b3RlPjwvZGl2Pg0KDQo8cD48L3A+CgotLSA8YnIgLz4KWW91IHJlY2Vp
dmVkIHRoaXMgbWVzc2FnZSBiZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUgR29vZ2xl
IEdyb3VwcyAmcXVvdDtrYXNhbi1kZXYmcXVvdDsgZ3JvdXAuPGJyIC8+ClRvIHVuc3Vic2NyaWJl
IGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQg
YW4gZW1haWwgdG8gPGEgaHJlZj0ibWFpbHRvOmthc2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVn
cm91cHMuY29tIj5rYXNhbi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbTwvYT4uPGJy
IC8+ClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIG9uIHRoZSB3ZWIgdmlzaXQgPGEgaHJlZj0iaHR0
cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi9DQUR5eDJWNmolMkJkbyUy
QkNtbVNZRVVyMGlQN1RVV0Q3eEhMUDJaSlBycUIxWSUyQlFFQXd6aHclNDBtYWlsLmdtYWlsLmNv
bT91dG1fbWVkaXVtPWVtYWlsJnV0bV9zb3VyY2U9Zm9vdGVyIj5odHRwczovL2dyb3Vwcy5nb29n
bGUuY29tL2QvbXNnaWQva2FzYW4tZGV2L0NBRHl4MlY2aiUyQmRvJTJCQ21tU1lFVXIwaVA3VFVX
RDd4SExQMlpKUHJxQjFZJTJCUUVBd3podyU0MG1haWwuZ21haWwuY29tPC9hPi48YnIgLz4K
--0000000000001b1ab405997ec622--
