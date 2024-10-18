Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUNHZC4AMGQEW3VNDAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 271649A37A4
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 09:52:51 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3a3ba4fcf24sf19464065ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 00:52:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729237970; cv=pass;
        d=google.com; s=arc-20240605;
        b=LmrM++Jqtz5BnBAspBwE58s+7Kfj76SsR3Mov4p5OvWeH+fZ7XLmQ775eCVQu2fbVb
         iu81VJKmx0kGqezN3lG3XNsA0k59HFGP2z2g/2zMdfdEy9Q2PFvNGxGk91wID16QkAF8
         hL/h187eRE5g0fqs68Uj3VpPcOwK8q/MFih0dhCQXqpqIryX9FnKddk+v9xwP+wcLqhA
         jklbe2py0R3lhLJAEq1WimiU9q7RN5K5KQnFKhtWHQqtIl6hnqAODBKOTeb+/6qhtXWM
         s68ZD9L2s93P2b5tZ9chrQmR6JsYEejFn/KY2B0qNDeNEHvQSuHCbZbBMvnYNV3fuBOt
         eDOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ox1OF6Df0s/KcA+w9dumTkksELy8+K/p1jQ2ZINWy0o=;
        fh=r7R5I1D2EmrxQJ3yoFXFdrVhbe4bzxEK5YmdawNh56E=;
        b=NOAMwwzKIlTDGtB04ag7oA0+MbXA38G/Y/mb6W+uO95UNDqNmq11+VhdlhcPUfaxS6
         I9y1oJU0wBVZEQ0dDcpKynkHCRyoLFzf4Kw2qdVyxHMjP744iDaWcSvUbruSHtCELRTL
         NwMAtZqeJM4lAPyoh7rZ1OZowNzo2YqBaBCrTrfPO7LCwWKOme/tZXPliS03pCo3IK0p
         JGEMk5fQ+FqbkiRTbcbY06VEU/87fiWGrK33JKIIzR+ML6fE/LchNRg8fDZtDwYjER4z
         gaGS3mb3dUhWPI6ZuXIY3zb6rrg5fIKvP5Bm1ScZHND9rZqcatri4MzK601oaHCuLSOq
         6w1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IB0+FQMA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729237970; x=1729842770; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ox1OF6Df0s/KcA+w9dumTkksELy8+K/p1jQ2ZINWy0o=;
        b=H8508p4VYnkKasKiL3sgDdkvHKkpt4hrWPNiMzRg07H0e7eQnuuB22xATtjl4KgAc+
         HE47lpuL0PWVY6toOrktYpXC450NmOS91P1479W0tXgdyIR4DeOio5JOekJuDGmvWKZt
         5TA3UZ9QxDX9IwsOX30as43b3IuLWfkJW9rCqWbadSzxRq9zTZcMBEJcXTJaau45kVGE
         DV3uT2AMaSzxvEugp5HY6R+JLxUtR/Lw0ln2qbQZM4VwCqEYqCh+xtPpMk7lAT0GSdt4
         4iyqz2RIyZqgGVVZArcedvHo2i80g5DTx5Zkz0RMAhG+noE4kPg4G3oTTtGPCdoy3fJA
         KpVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729237970; x=1729842770;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Ox1OF6Df0s/KcA+w9dumTkksELy8+K/p1jQ2ZINWy0o=;
        b=SujOGOtdTywPhXyyiXB73eVpBvV6NdkRf3dHVxlL4xsnxoNyNk368PpXKTdaA9U5rv
         hK713Ampy8ASYjJlQ/J2Vq7zVBuULAC+p+igPXMmYboFsxPMuu12nILc0tgn01bHUSZn
         xjTcNTMqkGKfaqh/LvlBcv7yArGnHqmrjcsA7YDhGV/GT8LebcFmWn/dfHz0ZaUkzFjg
         dWk5D+jh8VnV6gsriL09A9ViXn7lTv+jaPnX6ZNc2Z1oFP4YL/2jv1uVXenrFwFwr30k
         UzPIUWqKezGOu7mV5wohxpglWm9JlSVkwtBXt1yUH9C0tQSgWl73ALzWbeozveIGwb0V
         F1PQ==
X-Forwarded-Encrypted: i=2; AJvYcCXXYk0v6LrvdRwv9s6IfHRSB/rEybb+W2mOkPGu67ShoZzkZFdHlpGdDVc9G2Kj30xIf++dVg==@lfdr.de
X-Gm-Message-State: AOJu0YxacfsND7U4J+FmRY+muib6BkIOJaEphsJCW9oLgLIx2hzUM6ia
	ZT2R6ma9lgpkv8R4rwNii7EbOuohUIZlAf74/xY1ux84vkDzMq2M
X-Google-Smtp-Source: AGHT+IGilv0FICQEnaI/15xR0J0AwFxhctM7U+DW6Y4AcPKpMaKLzMATd/7f1lcpIuqJ5JYbC+6kXw==
X-Received: by 2002:a05:6e02:138a:b0:3a3:4477:e2eb with SMTP id e9e14a558f8ab-3a3f40b7333mr14852015ab.21.1729237969783;
        Fri, 18 Oct 2024 00:52:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1485:b0:3a1:96f6:f0f2 with SMTP id
 e9e14a558f8ab-3a3e4ae3682ls8549235ab.1.-pod-prod-02-us; Fri, 18 Oct 2024
 00:52:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXfZmoqmGyd/PHsHRpXrqf9Sxuve8oijdEcbrS1yLzyF0EQXo5OveMzKCp8GWIOOcjwrN+Dis6MWDk=@googlegroups.com
X-Received: by 2002:a05:6e02:1fe7:b0:3a3:b3f4:af42 with SMTP id e9e14a558f8ab-3a3f405e452mr15370345ab.7.1729237968865;
        Fri, 18 Oct 2024 00:52:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729237968; cv=none;
        d=google.com; s=arc-20240605;
        b=jvbvVUcpEn/nq55SslwFp0FDjZytrwel3HlFhis2y2MKttLeAEm5AMFiFyl5F/E8Yd
         YXsbL9l3vQb4/H+2HCDRLMjruuQXs3ZIc4Q6ToKlzhVhKcU8sHTrW5P2jeHr42r3CNux
         3l3Po69Sig7urIoaTSNk7EIdP1Uue68Izj5+QHdFWbn7586YYRvK1pmADOiyt3Smfbi7
         vhxggVerjvDjn7ssEgAaIjvmBgnHQazidIetNZo8TcINiElg3RUfYT8hi5CFJP4b+BOV
         6TlyMutz/S2euvrT8vYfTInP6NfRzo2bUf2j2E3YsE6DL2afEHy6Dr0HkyXrBt4gBRHF
         qEGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=t1yGhxObWkPiVeQcvLuPlgwyuxcYZynMlSzlofUMrMY=;
        fh=U4xuK5jNxeOWJhVt1BwY3f1ig69xZuaIqQuT5mWfNZk=;
        b=ROdaqsQsqKURMO+m2hqu1V2BlxaU2s3jO/FCRMsh8bOFBkGXqWabQSjXcLhECOQHSb
         OYUPtidntfA8T7stHLKQyyAVDLnKHe1V2+AN5Wpjcx9T/F7RQvdKFu8cTU4aw1i0XWUO
         jG8B6pC7hbk/j31hOdTGdeLD6hTh+/PopyeBm/JlfWRBCv4Uj/zd2w4EPyX0ZzNUjhmX
         qdLVTAWbCbn/EkxmiJlrHHjLTvR9Qz2YucJ48WYiZV0ib1EaDPCi5BP0D/aPe8Y96tsx
         AfmdMhsihQGTeEVHMz/vzOsqRWoqfQhZ7gL+N61UoyDz2Cxhxr2Dk8PFMn57SNmISovJ
         JLoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IB0+FQMA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3a3f4059599si439785ab.5.2024.10.18.00.52.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 00:52:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-71e585ef0b3so1483782b3a.1
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 00:52:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUmVtnoHYTGcR+/lxsJAT4spmMJHnJwPD3WCin1l5lFJRd/gwtj2F0jWqnW7h24eoJnPwW4OCgGm9I=@googlegroups.com
X-Received: by 2002:a05:6a21:3a94:b0:1d9:2453:4343 with SMTP id
 adf61e73a8af0-1d92c57e30dmr1939838637.41.1729237967749; Fri, 18 Oct 2024
 00:52:47 -0700 (PDT)
MIME-Version: 1.0
References: <20241017214251.170602-1-niharchaithanya@gmail.com> <CA+fCnZfT80jDpQ5Dh-4w+eGQGoJQYd-F6h=_qNP4aw81TUMOCw@mail.gmail.com>
In-Reply-To: <CA+fCnZfT80jDpQ5Dh-4w+eGQGoJQYd-F6h=_qNP4aw81TUMOCw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Oct 2024 09:52:09 +0200
Message-ID: <CANpmjNMG_YZa4ZB2xPYbf=fq9=tgn+8TOwURDiHPZtgXCe=iPg@mail.gmail.com>
Subject: Re: [PATCH] kasan:report: filter out kasan related stack entries
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Nihar Chaithanya <niharchaithanya@gmail.com>, dvyukov@google.com, 
	Aleksandr Nogikh <nogikh@google.com>, ryabinin.a.a@gmail.com, skhan@linuxfoundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=IB0+FQMA;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, 18 Oct 2024 at 02:44, Andrey Konovalov <andreyknvl@gmail.com> wrote=
:
>
> On Thu, Oct 17, 2024 at 11:46=E2=80=AFPM Nihar Chaithanya
> <niharchaithanya@gmail.com> wrote:
> >
> > The reports of KASAN include KASAN related stack frames which are not
> > the point of interest in the stack-trace. KCSAN report filters out such
> > internal frames providing relevant stack trace. Currently, KASAN report=
s
> > are generated by dump_stack_lvl() which prints the entire stack.
> >
> > Add functionality to KASAN reports to save the stack entries and filter
> > out the kasan related stack frames in place of dump_stack_lvl().
> >
> > Within this new functionality:
> >         - A function save_stack_lvl_kasan() in place of dump_stack_lvl(=
) is
> >           created which contains functionality for saving, filtering an=
d printing
> >           the stack-trace.

save_stack_lvl_kasan() tells me that it's saving a stack trace
somewhere. But this is actually printing. So the name here is
misleading.

We usually name things as <subsys>_foo if it's a function similar to
foo but for that subsystem.

So you can name it kasan_dump_stack_lvl.

> >         - The stack-trace is saved to an array using stack_trace_save()=
 similar to
> >           KCSAN reporting which is useful for filtering the stack-trace=
,
> >         - The sanitize_stack_entries() function is included to get the =
number of
> >           entries to be skipped for filtering similar to KCSAN reportin=
g,
> >         - The dump_stack_print_info() which prints generic debug info i=
s included
> >           from __dump_stack(),
> >         - And the function print_stack_trace() to print the stack-trace=
 using the
> >           array containing stack entries as well as the number of entri=
es to be
> >           skipped or filtered out is included.
> >
> > Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
> > Fixes: https://bugzilla.kernel.org/show_bug.cgi?id=3D215756
>
> Great start!
>
> One part that is missing is also filtering out KASAN frames in stack
> traces printed from print_track(). Right now it call
> stack_depot_print() to print the stack trace. I think the way to
> approach this would be to use stack_depot_fetch(), memcpy the frames
> to a local buffer, and then reuse the stack trace printing code you
> added.
>
> I've also left some comments below.
>
> Please address these points first and send v2. Then, I'll test the
> patch and see if there's more things to be done.
>
> On a related note, I wonder if losing the additional annotations about
> which part of the stack trace belongs with context (task, irq, etc)
> printed by dump_stack() would be a problem. But worst case, we can
> hide stack frame filtering under a CONFIG option.
>
> > ---
> >  mm/kasan/report.c | 92 +++++++++++++++++++++++++++++++++++++++++++++--
> >  1 file changed, 90 insertions(+), 2 deletions(-)
> >
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index b48c768acc84..c180cd8b32ae 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -39,6 +39,7 @@ static unsigned long kasan_flags;
> >
> >  #define KASAN_BIT_REPORTED     0
> >  #define KASAN_BIT_MULTI_SHOT   1
> > +#define NUM_STACK_ENTRIES 64
>
> If we keep this as 64, we can reuse KASAN_STACK_DEPTH.
>
> However, I wonder if 64 frames is enough. Marco, Alexander, Dmitry,
> IIRC you did some measurements on the length of stack traces in the
> kernel: would 64 frames be good enough for KASAN reports? Was this
> ever a problem for KCSAN?

It was never a problem and 64 was enough, even when unwinding through
interrupt handlers.

It should just use KASAN_STACK_DEPTH.

> >
> >  enum kasan_arg_fault {
> >         KASAN_ARG_FAULT_DEFAULT,
> > @@ -369,12 +370,99 @@ static inline bool init_task_stack_addr(const voi=
d *addr)
> >                         sizeof(init_thread_union.stack));
> >  }
> >
> > +/* Helper to skip KASAN-related functions in stack-trace. */
> > +static int get_stack_skipnr(const unsigned long stack_entries[], int n=
um_entries)
> > +{
> > +       char buf[64];
> > +       int len, skip;
> > +
> > +       for (skip =3D 0; skip < num_entries; ++skip) {
> > +               len =3D scnprintf(buf, sizeof(buf), "%ps", (void *)stac=
k_entries[skip]);
> > +
> > +               /* Never show  kasan_* functions. */
> > +               if (strnstr(buf, "kasan_", len) =3D=3D buf)
> > +                       continue;
> > +               /*
> > +                * No match for runtime functions -- @skip entries to s=
kip to
> > +                * get to first frame of interest.
> > +                */
> > +               break;
> > +       }
> > +
> > +       return skip;
> > +}
> > +
>
> Please also copy the comment for this function, it's useful for
> understanding what's going on.
>
> > +static int
> > +replace_stack_entry(unsigned long stack_entries[], int num_entries, un=
signed long ip,
> > +                   unsigned long *replaced)
> > +{
> > +       unsigned long symbolsize, offset;
> > +       unsigned long target_func;
> > +       int skip;
> > +
> > +       if (kallsyms_lookup_size_offset(ip, &symbolsize, &offset))
> > +               target_func =3D ip - offset;
> > +       else
> > +               goto fallback;
> > +
> > +       for (skip =3D 0; skip < num_entries; ++skip) {
> > +               unsigned long func =3D stack_entries[skip];
> > +
> > +               if (!kallsyms_lookup_size_offset(func, &symbolsize, &of=
fset))
> > +                       goto fallback;
> > +               func -=3D offset;
> > +
> > +               if (func =3D=3D target_func) {
> > +                       *replaced =3D stack_entries[skip];
> > +                       stack_entries[skip] =3D ip;
> > +                       return skip;
> > +               }
> > +       }
> > +
> > +fallback:
> > +       /* Should not happen; the resulting stack trace is likely misle=
ading. */
> > +       WARN_ONCE(1, "Cannot find frame for %pS in stack trace", (void =
*)ip);
> > +       return get_stack_skipnr(stack_entries, num_entries);
> > +}
>
> Hm, There's some code duplication here between KCSAN and KASAN.
> Although, the function above is the only part dully duplicated, so I
> don't know whether it makes sense to try to factor it out into a
> common file.
>
> Marco, WDYT?

I would keep it separate, and get it working for KASAN first. There
may need to be fixes that only apply to one or the other, since this
code has been a little fiddly in the past. Once it's settled and
working, we can think about refactoring.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMG_YZa4ZB2xPYbf%3Dfq9%3Dtgn%2B8TOwURDiHPZtgXCe%3DiPg%40mai=
l.gmail.com.
