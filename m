Return-Path: <kasan-dev+bncBCR5PSMFZYORBKXWQ2BAMGQEJ35EX5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CBCE32E0F2
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 06:01:34 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id v19sf629902qtw.19
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 21:01:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614920492; cv=pass;
        d=google.com; s=arc-20160816;
        b=B55gayo5aZR0w+zWYKIz3CC79SYRfV/AGwFc9YrdFGdSXWRPUtY1No639cUQP04pCt
         LH0KN5sGGJQa81F8ZoMwGuxmC5XhVx+SMlMp6KGlXi0hPKPZ/7IZldAmyA6747yoW09+
         0gscXVBFbEypXK2vHS+XDICVrYOuPJlvfZcd300WlC+diQDvXsxOjS2G9lh4tueGA+2H
         ZPWkcOAEFauy+UVGXHRgzx3o7DGcXAU6ieBRL+LcrmnxwnMCI/CBQYeZYldHrOrUjuuj
         UiKILKbhdt1z9fIfBPRmhhqA1AAwA6oLvnSo7roCUR303tQwj2s4T8PtQkUYtQ7NZaXR
         klHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=DBybgT4QDeGo8C7sA9HX+WJp7qOW0LD6Do4qJpb0IGs=;
        b=DzrrRlS8tNB/S9hpuN20XUqYA2cIkYe6XFwylFTVCY6n/LQSRfgHuJsWI2OHGS5yj1
         +1K9nUVdsTZ3VOYg1UUDqQLIeNeNe0uY61DXbECeZzCGdbAd9x5lmWu3gd6coLzgeMTu
         3+EJaSZBF3IE6qpYeezDlohu9esxLYZvjiLZP5zdJPk0HCXYZTNqu/TQbM+F2Q3zft/O
         QVxUC4GdN7BCDK5SIKLjuKc65ra9EPJP/GmeBc29fRy9KrR55+4e8FEHlOMPQmImHzL7
         QQs+EoPBPQdfa/yHap4vBV2akzeEWN0+FydBKf5eOcHmC+M/jnoXd0QDxf4kqbFvzXEB
         INpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=sEe2yFiC;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DBybgT4QDeGo8C7sA9HX+WJp7qOW0LD6Do4qJpb0IGs=;
        b=gMyVIkXYD9XIDFnwW/Skit3hL7lhvaHzkvX7jeEAAfN/qvEfcn+JIQmuuNWAz5qCvz
         VsA6ubVy78QWnyPBfwVhOCH0NPiAJs/+zNm/vgE/gSfwveqbDUpqkuzSVjtoV2DWi0Ia
         bOo/URGd9832P7sk/66YmMOwLysdGNz0fOmhMFRN6Bj3ZuDEZlJlHn5buWbXUS9lDSLQ
         Ynp3hK/3/D9JbS3k8v20FKU10iJHHeOosWNpgQdZhKBMDbwdRatbv3XXw8FX3fsZVz9s
         Cr3hW7bxQc6ex03DOk4SNUzJSyx2ll12YkXcfnX2C3vxhlHCquvksPfvWPstt0s2GDhA
         K2cQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DBybgT4QDeGo8C7sA9HX+WJp7qOW0LD6Do4qJpb0IGs=;
        b=fsNpUxlDZF19ny5k8P+pVIkMEKkLwryhYnsCI9HwvS8UVjF6y+HYi/ohjN4+epgiba
         jNKm+aIHEvN/ptioybrjXk0QyWTi31yn9BrlqxHil8w16eSDh/4HTDZtz7F23gM+5rQ7
         7U1BxNCUO3WrA8cAcCTgmbLPowYgLtMWsyDR4H/EopQb4TA8q61p7TpHzrJ5DSMSfwus
         bbEPexCcUcpzphyNI9mxR18Dxm8drJLtJj1/61MsrAjShfk/0gDTfiLNjjvjHV/ANCpu
         hvuVQ7lwhU7GVXRLztUBhsnoiGX2wIF7+6YTHn7p01AVWI8I5Tk5p2jSakJZ/K2xq0WS
         DBQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530bNmEuMEDDQarZsgS9HzE33LBUFyZBkClmDuZmfjn+CjDxRq8G
	6nHCFDGXYP3vSuQhqLgv0AY=
X-Google-Smtp-Source: ABdhPJyNYDw5bVzyRc9iJK+uE2my64WvROrEadMSVR/kzKMvEePtx+EGiNmIdav7QGA4gy9f6JgTaw==
X-Received: by 2002:ac8:4905:: with SMTP id e5mr5046672qtq.55.1614920490200;
        Thu, 04 Mar 2021 21:01:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:731a:: with SMTP id x26ls2728816qto.2.gmail; Thu, 04 Mar
 2021 21:01:29 -0800 (PST)
X-Received: by 2002:ac8:6b97:: with SMTP id z23mr7229907qts.205.1614920489774;
        Thu, 04 Mar 2021 21:01:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614920489; cv=none;
        d=google.com; s=arc-20160816;
        b=GBGQLn8FXfQ9+5J3om59n+hBgjy0tPJs0GmgmTOJMuT0QlkF8iTrMawisOXHdI9dUS
         RTYWXtBmQjKZue/HSYBgmL1bonafdJ1NdE/+ZD2c6iVNfkI0dro2KpTT/k1QI+iGKGiU
         S5st7mI0o23OkAD7Xj1oL7TIplY9CNoK4YwbM/+0mgoX95h7IvT+IYfH4e5z+oe0ODde
         QhldQo8NH4iTbgyMBJ7qD4D5ABy+yKG3C5RDs8AW5VHZ4AXaeAINVgFyOkJMsNmGk9ja
         P/MrVD+0EesjFV1aTUTNB3K49glNrvjLUCgtnzjKc640IHrIy+P7wpc5mTo9n6sikpRj
         Eo4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=mVO4GQgAU6IhKYNMr3j4mcJ3VKCGNO/ioeOVs6BXPe0=;
        b=CsQBom5r+selrwP9zQByR8oABDCktJbJN98qsEjeMPTjXHy/V37RodroopbvyWq7Yt
         nk2yt158psqDI1hJV6JojzdL2wDROisr/H/ayJZ5qD17BpFJPyg1rDdO3kg40tlUUWMi
         LH+9L0+Kne1VLBVEcBWLZmJcqoTq+VqOEk7wu/emDHYVKH8qgzr3osk0l727Pa+2tmsa
         rP0/7G/x1bAVWwogugNmC66oi22lWMmm74VxsZkYO6N3B5CkIeCq5FUp20VQZbfwP9dq
         YuHS4qFBMweUGHBUDH2dSlLq2gUxEiuVzUG68LB27oXuqxkiG2j0kTwJoyrYrwdvXUnD
         8b7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=sEe2yFiC;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from ozlabs.org (ozlabs.org. [203.11.71.1])
        by gmr-mx.google.com with ESMTPS id g4si94448qtg.3.2021.03.04.21.01.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Mar 2021 21:01:28 -0800 (PST)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) client-ip=203.11.71.1;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4DsFv51fBxz9sWC;
	Fri,  5 Mar 2021 16:01:21 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Marco Elver <elver@google.com>, Christophe Leroy
 <christophe.leroy@csgroup.eu>
Cc: Alexander Potapenko <glider@google.com>, Benjamin Herrenschmidt
 <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Dmitry
 Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>,
 linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
In-Reply-To: <YEDXJ5JNkgvDFehc@elver.google.com>
References: <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
 <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu>
 <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu>
 <CANpmjNPYEmLtQEu5G=zJLUzOBaGoqNKwLyipDCxvytdKDKb7mg@mail.gmail.com>
 <ad61cb3a-2b4a-3754-5761-832a1dd0c34e@csgroup.eu>
 <CANpmjNOnVzei7frKcMzMHxaDXh5NvTA-Wpa29C2YC1GUxyKfhQ@mail.gmail.com>
 <f036c53d-7e81-763c-47f4-6024c6c5f058@csgroup.eu>
 <CANpmjNMn_CUrgeSqBgiKx4+J8a+XcxkaLPWoDMUvUEXk8+-jxg@mail.gmail.com>
 <7270e1cc-bb6b-99ee-0043-08a027b8d83a@csgroup.eu>
 <YEDXJ5JNkgvDFehc@elver.google.com>
Date: Fri, 05 Mar 2021 16:01:15 +1100
Message-ID: <874khqry78.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b=sEe2yFiC;       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted
 sender) smtp.mailfrom=mpe@ellerman.id.au
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

Marco Elver <elver@google.com> writes:
> On Thu, Mar 04, 2021 at 12:48PM +0100, Christophe Leroy wrote:
>> Le 04/03/2021 =C3=A0 12:31, Marco Elver a =C3=A9crit=C2=A0:
>> > On Thu, 4 Mar 2021 at 12:23, Christophe Leroy
>> > <christophe.leroy@csgroup.eu> wrote:
>> > > Le 03/03/2021 =C3=A0 11:56, Marco Elver a =C3=A9crit :
>> > > >=20
>> > > > Somewhat tangentially, I also note that e.g. show_regs(regs) (whic=
h
>> > > > was printed along the KFENCE report above) didn't include the top
>> > > > frame in the "Call Trace", so this assumption is definitely not
>> > > > isolated to KFENCE.
>> > > >=20
>> > >=20
>> > > Now, I have tested PPC64 (with the patch I sent yesterday to modify =
save_stack_trace_regs()
>> > > applied), and I get many failures. Any idea ?
>> > >=20
>> > > [   17.653751][   T58] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
>> > > [   17.654379][   T58] BUG: KFENCE: invalid free in .kfence_guarded_=
free+0x2e4/0x530
>> > > [   17.654379][   T58]
>> > > [   17.654831][   T58] Invalid free of 0xc00000003c9c0000 (in kfence=
-#77):
>> > > [   17.655358][   T58]  .kfence_guarded_free+0x2e4/0x530
>> > > [   17.655775][   T58]  .__slab_free+0x320/0x5a0
>> > > [   17.656039][   T58]  .test_double_free+0xe0/0x198
>> > > [   17.656308][   T58]  .kunit_try_run_case+0x80/0x110
>> > > [   17.656523][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0x5=
0
>> > > [   17.657161][   T58]  .kthread+0x18c/0x1a0
>> > > [   17.659148][   T58]  .ret_from_kernel_thread+0x58/0x70
>> > > [   17.659869][   T58]
> [...]
>> >=20
>> > Looks like something is prepending '.' to function names. We expect
>> > the function name to appear as-is, e.g. "kfence_guarded_free",
>> > "test_double_free", etc.
>> >=20
>> > Is there something special on ppc64, where the '.' is some convention?
>> >=20
>>=20
>> I think so, see https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64=
abi.html#FUNC-DES
>>=20
>> Also see commit https://github.com/linuxppc/linux/commit/02424d896
>
> Thanks -- could you try the below patch? You'll need to define
> ARCH_FUNC_PREFIX accordingly.
>
> We think, since there are only very few architectures that add a prefix,
> requiring <asm/kfence.h> to define something like ARCH_FUNC_PREFIX is
> the simplest option. Let me know if this works for you.
>
> There an alternative option, which is to dynamically figure out the
> prefix, but if this simpler option is fine with you, we'd prefer it.

We have rediscovered this problem in basically every tracing / debugging
feature added in the last 20 years :)

I think the simplest solution is the one tools/perf/util/symbol.c uses,
which is to just skip a leading '.'.

Does that work?

diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index ab83d5a59bb1..67b49dc54b38 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -67,6 +67,9 @@ static int get_stack_skipnr(const unsigned long stack_ent=
ries[], int num_entries
 	for (skipnr =3D 0; skipnr < num_entries; skipnr++) {
 		int len =3D scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[ski=
pnr]);
=20
+		if (buf[0] =3D=3D '.')
+			buf++;
+
 		if (str_has_prefix(buf, "kfence_") || str_has_prefix(buf, "__kfence_") |=
|
 		    !strncmp(buf, "__slab_free", len)) {
 			/*



cheers

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/874khqry78.fsf%40mpe.ellerman.id.au.
