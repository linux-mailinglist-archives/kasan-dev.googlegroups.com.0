Return-Path: <kasan-dev+bncBDUPB6PW4UKRBDFNQWAQMGQE2MRDQ7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 40251313703
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 16:19:41 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id v108sf8594075otb.6
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 07:19:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612797580; cv=pass;
        d=google.com; s=arc-20160816;
        b=xJko23P5bM9ErNd2XFTSAFSMh+s/1yu1MpfVpaz5LCXg8Yf79wAaGVnJqPyomB/cLf
         kDBzMtcnQD9m7jpTiqfvzUHO/2KlsBGSYnjx+Ah4otJKhhb9JvhS96aCCnwZf4n9M/XZ
         XIL/tUGlV46vQ1iS5qKMGbnw3JAYIm15J8jAnZJ9052CsOKupBHskHlnJJ9lPEH5Y14p
         G/fLmekZSDxzjDMDMWYgejaNqzUt/U96U3bJtN/FD9wFrlDbN0KRCcQCmZK36jHI2W5e
         m8qNESUcGiL5Wz6/8fHWpi/+IwLzi659RkHF6QBOR4g276m+LXpLYyBZ2nEEKplhRfdo
         qFbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:from:cc:to:subject
         :content-transfer-encoding:mime-version:references:in-reply-to
         :user-agent:date:sender:dkim-signature:dkim-signature;
        bh=K1pAKU9t4DqT5Zj/Lak3X7rSUtpiO6i6T3rxhRqkjtI=;
        b=knHV6sD1gkfCg/nBUg+y2Q/jwDCBaFRTyK+nNoQ+33jTcjDy4nHDAlDeSD7TB9/MhI
         t8aRt8EzIDKQEtAgw8/HIK1WWwA4AzC9YEkMZkN4CxmIBUM3F+xNkm/K7/ceQzyaEaD9
         3okX7E4wiLU26il4ogpuN8J33tDBj7uBFoXw3cwMK2tk6lLQJdZuj1a5owKkSPlvWejN
         swcSm7vsxssLpHffeyvZVUjA3bTF/d1fvO8j3yVCohC7eOY1ko7EAV/s0fxm7PJHRwRX
         aRiF1tEAiDgb+Xbqr0UNskaApT/R8bleBxuKzoLc6rRFgDYaE3zr2Gp+yDGxaL96lslA
         9nww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=bFgYcI0t;
       spf=pass (google.com: domain of achirvasub@gmail.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=achirvasub@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:user-agent:in-reply-to:references:mime-version
         :content-transfer-encoding:subject:to:cc:from:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K1pAKU9t4DqT5Zj/Lak3X7rSUtpiO6i6T3rxhRqkjtI=;
        b=nCYu+EXm1ngBzBFw1nYlC02n3bElIHMJe0OIz9GP2WMKaxIX8kdn61QVZC7u3bcdfD
         3BWclVbnNYeBjTYJKJDZOCykrJ/7Y38znrlCbi1XP6utfACjlPsJTffRaZmO3BaUwvU0
         6j8PuKWAybhYBbHAxttJrAQCLiaFnKlFHyPF9Y7PYmK+niCErZhMlo9e8YEvwqtPP3tF
         NQcKf5A9H/GNUg0sHYcqcA3V2qcKJX5SoS4B/wEcrKKFA8UCxuoLo4ivB76hMew1wgna
         GQarfbRT3Zh36Jle0+EysdV3bHcvzTMAoJMgD4/HND1jZ6365j7MD1KS44vNKzlImGPy
         jRBA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:user-agent:in-reply-to:references:mime-version
         :content-transfer-encoding:subject:to:cc:from:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K1pAKU9t4DqT5Zj/Lak3X7rSUtpiO6i6T3rxhRqkjtI=;
        b=jYdzUWCaG71DhFKXUyU0+XTvHppFJXfoW1V3miYPEThxAXhedxTArN4ieawjxJcJiF
         7I0T08iRA/N5Tkodxsr0D6NbY9QIZ+Q43UdcCGyDCKKrde2rSYrGmIBydQnr7EOrBEKt
         lT0oBGTt/A5v/NEFwRLPly3mbGtiQ7FOEGI1BFcqTm9DrLA6q+EpNQGcuaFWkACnD1kh
         R9n/L4GJViuUnRIm9KuLZPmvbHsn1WJYTLvUxOLnlrzFtzUbBccqO5BGKSbwWi1GNBIW
         lUVyC1sqNDvVvrKfsNkmjgXw7TWkGNUpWHz1kje3z3FcDL1nCSTRKzCzAXB/YM3LO270
         xKvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:user-agent:in-reply-to:references
         :mime-version:content-transfer-encoding:subject:to:cc:from
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=K1pAKU9t4DqT5Zj/Lak3X7rSUtpiO6i6T3rxhRqkjtI=;
        b=eYPlxUgBXXlLR+2I4P8Snq+mTKrmr7mNwQ7UjV3nQd/4UUuMxZ0HVMQkt1ASTy135a
         adKZYbRD126uqEtnfcrPm5CTPd8beOFbLU8bYu4C3d//V8iFm3F5MjhFaYDnlFSHPhMf
         k5OUeY0lu86m8bUb4b88r5kXBosuzSj31b1c7qqxupKC/VQ2DPtaWmqX+p5gBJ6Cecjy
         dPHByapkjCB/W4KN/I2h9Iv1UGswvWtOVlZ2RX72WjFnm/uU8DSCFxWnr4IsH8u23J/N
         6SmVUOolQ9Fl6iTUKUYAaopKGp8bq3iUDFliI6qDVDS2AqNEyMO4+EeT9U1GWGXsTTYR
         NXww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530RTxaDdAvDIN/mXMaotM9OlLbFabzz903xbQ5gVOaBqVaMzDpJ
	90lj2lqzBBV9YCe3+/ARhrg=
X-Google-Smtp-Source: ABdhPJzsoIL7Vph7lkTcBamnqCN3cXjxcstPTB3Dv82sAPb3e9jSE1UhvDGp7K2J16zvE8fdsy8P6w==
X-Received: by 2002:a05:6830:1496:: with SMTP id s22mr3461558otq.249.1612797580247;
        Mon, 08 Feb 2021 07:19:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1912:: with SMTP id l18ls970079oii.1.gmail; Mon, 08 Feb
 2021 07:19:39 -0800 (PST)
X-Received: by 2002:aca:f12:: with SMTP id 18mr11761303oip.106.1612797579894;
        Mon, 08 Feb 2021 07:19:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612797579; cv=none;
        d=google.com; s=arc-20160816;
        b=iDLPzkYVs8ja8Hi7krotGSUEdFF46eu6qLPx0eHrjqeUTM5gab81eM12SY9fJsYGth
         D2EeLLgin9KwDVLEqMR7J58XC0hpxivbtJhlf/Hps+/E6sAP+O+sXhlzc8iLHdHeBfvP
         BqvUk1IMbTCfFBSg9dsdlmj4aOvZUMQRBYBx3oBWNl7SDp0uRm5v1eOhqO+hBW5pX8Ml
         ec+sNSqKRCuo28h+ovXsLlcepTsoEn+tAoTjfBPqOoqveDqjM4PhOerWNyVhpO3rxTUz
         pVDtj/xeZJIQAQ2KmF8m3HSnESUscB+ujrxDzuLaJgZfQsuTuObkY6Uu7FHLg3JAb7l9
         N6YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:from:cc:to:subject:content-transfer-encoding
         :mime-version:references:in-reply-to:user-agent:date:dkim-signature;
        bh=lfyLu2giIvQHAiyFdLqX9LY0OGrzlVaPuwSjSMWgNvo=;
        b=GPgoV3+he30Rx1GLUoiOxpHK58N4ZBkMNxX7OA0y57PBQVIKi1nfJK0nCe81vNLve6
         VN0eY537lYQFPKfn0KdatO41HVIqlCpxGQc4X5jYGBNZC2ikyB3m4UqrsBcsyhVKZ3Hu
         jqrRiCFBfmpSwFjXFhepo5GGE0Q0A2ZVa9Tq0qwa9J+9x9RwPJMyJAY2ZDxzTKfx+nDn
         9vBR+wxXoI2YRRd+sXwU4Rsp1YK+ov1zi0x9vz3ApaOBfLEEpo5vdB97o3aEl+5JnXTo
         rfFoHunOwc5kbTyn+RbK+3al3MieVBQ+hlLl0Pha8YlPNvwnVIGb4LYD5km8WURbwk6p
         Y9XA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=bFgYcI0t;
       spf=pass (google.com: domain of achirvasub@gmail.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=achirvasub@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id y192si322362ooa.1.2021.02.08.07.19.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Feb 2021 07:19:39 -0800 (PST)
Received-SPF: pass (google.com: domain of achirvasub@gmail.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id x3so8618047qti.5
        for <kasan-dev@googlegroups.com>; Mon, 08 Feb 2021 07:19:39 -0800 (PST)
X-Received: by 2002:ac8:5909:: with SMTP id 9mr15873605qty.39.1612797576127;
        Mon, 08 Feb 2021 07:19:36 -0800 (PST)
Received: from [192.168.1.171] (pool-68-133-6-116.bflony.fios.verizon.net. [68.133.6.116])
        by smtp.gmail.com with ESMTPSA id m64sm16848259qkb.90.2021.02.08.07.19.35
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Feb 2021 07:19:35 -0800 (PST)
Date: Mon, 08 Feb 2021 10:19:33 -0500
User-Agent: K-9 Mail for Android
In-Reply-To: <20210208121227.GD17908@zn.tnic>
References: <YCB4Sgk5g5B2Nu09@arch-chirva.localdomain> <YCCFGc97d2U5yUS7@arch-chirva.localdomain> <YCCIgMHkzh/xT4ex@arch-chirva.localdomain> <20210208121227.GD17908@zn.tnic>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
Subject: =?UTF-8?Q?Re=3A_PROBLEM=3A_5=2E11=2E0-rc7_fail?= =?UTF-8?Q?s_to_compile_with_error=3A_=E2=80=98-m?= =?UTF-8?Q?indirect-branch=E2=80=99_and_=E2=80=98-fcf-p?= =?UTF-8?Q?rotection=E2=80=99_are_not_compatible?=
To: Borislav Petkov <bp@suse.de>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>,Alexander Potapenko <glider@google.com>,Dmitry Vyukov <dvyukov@google.com>,Marco Elver <elver@google.com>,Arnd Bergmann <arnd@arndb.de>,linux-arch@vger.kernel.org,linux-kernel@vger.kernel.org,kasan-dev@googlegroups.com,jpoimboe@redhat.com,nborisov@suse.com,seth.forshee@canonical.com,yamada.masahiro@socionext.com
From: AC <achirvasub@gmail.com>
Message-ID: <82FA27E6-A46F-41E2-B7D3-2FEBEA8A4D70@gmail.com>
X-Original-Sender: achirvasub@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=bFgYcI0t;       spf=pass
 (google.com: domain of achirvasub@gmail.com designates 2607:f8b0:4864:20::832
 as permitted sender) smtp.mailfrom=achirvasub@gmail.com;       dmarc=pass
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

That did fix it, thank you!

On February 8, 2021 7:12:27 AM EST, Borislav Petkov <bp@suse.de> wrote:
>On Sun, Feb 07, 2021 at 07:40:32PM -0500, Stuart Little wrote:
>> > On Sun, Feb 07, 2021 at 06:31:22PM -0500, Stuart Little wrote:
>> > > I am trying to compile on an x86_64 host for a 32-bit system; my
>config is at
>> > >=20
>> > > https://termbin.com/v8jl
>> > >=20
>> > > I am getting numerous errors of the form
>> > >=20
>> > > ./include/linux/kasan-checks.h:17:1: error: =E2=80=98-mindirect-bran=
ch=E2=80=99
>and =E2=80=98-fcf-protection=E2=80=99 are not compatible
>
>Does this fix it?
>
>---
>
>diff --git a/arch/x86/Makefile b/arch/x86/Makefile
>index 5857917f83ee..30920d70b48b 100644
>--- a/arch/x86/Makefile
>+++ b/arch/x86/Makefile
>@@ -50,6 +50,9 @@ export BITS
> KBUILD_CFLAGS +=3D -mno-sse -mno-mmx -mno-sse2 -mno-3dnow
> KBUILD_CFLAGS +=3D $(call cc-option,-mno-avx,)
>=20
>+# Intel CET isn't enabled in the kernel
>+KBUILD_CFLAGS +=3D $(call cc-option,-fcf-protection=3Dnone)
>+
> ifeq ($(CONFIG_X86_32),y)
>         BITS :=3D 32
>         UTS_MACHINE :=3D i386
>@@ -120,9 +123,6 @@ else
>=20
>         KBUILD_CFLAGS +=3D -mno-red-zone
>         KBUILD_CFLAGS +=3D -mcmodel=3Dkernel
>-
>-	# Intel CET isn't enabled in the kernel
>-	KBUILD_CFLAGS +=3D $(call cc-option,-fcf-protection=3Dnone)
> endif
>=20
> ifdef CONFIG_X86_X32

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/82FA27E6-A46F-41E2-B7D3-2FEBEA8A4D70%40gmail.com.
