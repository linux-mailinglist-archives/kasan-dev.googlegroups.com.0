Return-Path: <kasan-dev+bncBDEKVJM7XAHRBJX4WSBAMGQECI5RCPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id E1E4533A1AF
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 23:35:18 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id i19sf13757861edy.18
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 14:35:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615674918; cv=pass;
        d=google.com; s=arc-20160816;
        b=MR1unYYyEOPbWrr1joHRkTFdRKDtNBDwbz+6EQoq1Ht1Ve1xOJubjdIHLES13N5v4h
         jsYEIf0jbQSx97CMKVMSievZi2b/MaBpwHe9P7RSH4jTcjaWrK8+TSgp6/l6UPCcKZWA
         BqbTzKXLCrDeIF5vcJZljzpa8M5UToiUalIWCmqCBp+mpi3mhojCbT3I4zaFaalCdnz5
         1cTtwARvVmYaEj2kSF9k2qaKkWd42jgaS+M0UlVPaixtkVXapY0wVD6lEF2wfqCeFJ9R
         GNGyP0lbKDGBSqizqhHYevDczKfy4edGL1uWIUcvLhkmoMIvx9Gy0tIZkt2TmcFuvQQz
         Tp8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=iPMiRXmS7kbSWrulh0wRNgJMVYc6GclPN19uLHll744=;
        b=LiXINDs9S1q/m4izZUupZH7gdfWE4TPoq6s0frVax4r6rRiaaLnio2QXjLaZqvho/Q
         eUENVqcpwUAi+pwlCVU44YijKPqBoGLf2tRowR4Cr+75yu6yqwNdlnavAXQLhsiUkySs
         UnVdVbCdJ3Z/Sc35QNA04PTAUqiTkb4W4YYkQHYV/Bp8lK5JTwXNst8oC6WPv0k0lyA3
         0brP0y56cNzfjH9lE+VdW9hDbHsvAgpwyZvN/J1MOt04FpPmEqIZNl3/Ql6UGdZX9bVP
         QZ1JBqem9MH3JwCzzCdg6cbt7/Q6Yzb+omS3+X+qMFK5upZUVRK8TW4pUuqOvsb5Ucud
         YkbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.17.24 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iPMiRXmS7kbSWrulh0wRNgJMVYc6GclPN19uLHll744=;
        b=VDaKDOUU9q4rxvLvGHqf3l1JqLjeyUlMytCmDjFnsa0Mki+7LS9fSnCId6LodVwcj0
         FBHaIUlkb+zNzrVq6gfYasw+Jjj0WPOjE9aIhvGkQ6vi34Jm6tjboI9bOZtfRMd4+RlP
         fs3yc9TPBPyy3jBXhGV80eQN6UoKsDvoruNEA49RSxP3gS9EFQS5646fO5LhjbfoaoRb
         x0080dgIdZOnmYw2m5KpjkOpED5hrGn+HAquuAEv66TxjON4Wr4DMiCQv0RNsW689R5G
         oG6ESRK1F0wuaWn1px+vLj4vO+X06feBj+kjS42ckioYjb7FbYs1tNaafhCx4byBYx8l
         ev0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iPMiRXmS7kbSWrulh0wRNgJMVYc6GclPN19uLHll744=;
        b=qN0NKBPiTPRjZjP0teRRcY5cnlK08Jh+OL0glSFYicqWGc3BdRF9fZiVphogwJsGHG
         HFQ/P1AwgxFGbeycTN0AsTIG7RDkpBXaQvWv4LuVZPFTDPPNgpEvyxZ13F2Mh3sGdwQL
         Qtu3loiqjkKpdxVtdBLOY4KLwJksiSguxi5fdgCdrmCT5if6gS3/AYr79VVEg3p3h5Rk
         E+HaW2mD+OgynWYLtw3hRuB73WotJvQhSfuVrM+K4uIAG3mVDbBmf0fpAxTDMbTglFT2
         XOXcxYTDA9+faN5W+8jOy72ujfWHnl+Zdp0qs6NKUB7xIf0T/wwC2OeqVRzZQFwZ0OJ4
         8WBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532kNCyV36TGOqPYQZcwrLAWrY8aZzroeRvfLRGohW9zgllmLxBs
	DoMHezDrNgB6a+t5v4+gDYk=
X-Google-Smtp-Source: ABdhPJzbqw3z9owdzTne6XPAAwOTH3ZH/UHHWUMfGUHBxCpuMHm6/wYdFFmewnf/7fvVEeUYAfPMFw==
X-Received: by 2002:aa7:c6da:: with SMTP id b26mr22245426eds.254.1615674918659;
        Sat, 13 Mar 2021 14:35:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:3f15:: with SMTP id hq21ls4077805ejc.9.gmail; Sat,
 13 Mar 2021 14:35:17 -0800 (PST)
X-Received: by 2002:a17:906:7d82:: with SMTP id v2mr5140766ejo.524.1615674917813;
        Sat, 13 Mar 2021 14:35:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615674917; cv=none;
        d=google.com; s=arc-20160816;
        b=qIZRdMI3qDcSRpzslk38gffvHcmpdJkKxgBWi3kRmrl8IonTGZDkeukLe3jvf+bN4/
         kbQYhBx7JHoxU3Xx0yxBZz9a1cIR42efQ9f2IO+Hkb/OkUWj0L+Ao5QTLjG+poblNgkk
         t2zdzBtFKdhlWwPn/3edB8bXcxfhsVpYfRpXkqRt7B2YUyGfQMYK7pG+TGIgGnnArM+5
         aH+8mDCTRBWoE2mujpVfsb8UVUMwQTotvlfUt6nD4sMW+ESlXg6gWe6jeVoc9S3P2MYN
         PFDOd1USZZja83fO55LC+YoOibLlWBxymzFabUV7XsHxYuZHTUsu2iQtW+BBxBfwkmuD
         5X9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=ITX0P9iDV1DnFJeATPTGZWr1uak95/r6ApalBmvcPNE=;
        b=XAMrOLavr13dmggZWRNcWQtvK2L/fctUAJvKmeFAW3rhk7+R7ExKCBasF/p3leht9p
         Wn9KviMBdnjtFbiLQV1l3ukj7b2rswv41NUXIjNNr6bTUPYn7DFvkqF9qGM/NmMDK8UR
         Ltey1w2UqboPef1fOu0sjqQ1rvOD2RSc3eCiB9GlRamMzQO3wCpuUnbR+3lXp+VhfznW
         HWSUO2mOs5wrNkq+T/GXRaqqyOPH1ooDEKIfSDDLTczUv2Y8OjGsAyqHNb3LUW0RqyUQ
         Uqt7AK43QXzRlR0gpNfUJEUyVhI1BfR/G45uNh+dIBuhAHiUPjgTos6mVHVicwwsqqjN
         v/VQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.17.24 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.17.24])
        by gmr-mx.google.com with ESMTPS id w5si337854edv.1.2021.03.13.14.35.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 13 Mar 2021 14:35:17 -0800 (PST)
Received-SPF: neutral (google.com: 212.227.17.24 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.17.24;
Received: from mail-ot1-f52.google.com ([209.85.210.52]) by
 mrelayeu.kundenserver.de (mreue108 [213.165.67.113]) with ESMTPSA (Nemesis)
 id 1MzQXu-1lhOXV05iK-00vOfY for <kasan-dev@googlegroups.com>; Sat, 13 Mar
 2021 23:35:17 +0100
Received: by mail-ot1-f52.google.com with SMTP id 68-20020a9d0f4a0000b02901b663e6258dso3303802ott.13
        for <kasan-dev@googlegroups.com>; Sat, 13 Mar 2021 14:35:16 -0800 (PST)
X-Received: by 2002:a05:6830:148c:: with SMTP id s12mr8850529otq.251.1615674915810;
 Sat, 13 Mar 2021 14:35:15 -0800 (PST)
MIME-Version: 1.0
References: <20210225080453.1314-1-alex@ghiti.fr> <20210225080453.1314-3-alex@ghiti.fr>
 <5279e97c-3841-717c-2a16-c249a61573f9@redhat.com> <7d9036d9-488b-47cc-4673-1b10c11baad0@ghiti.fr>
 <CAK8P3a3mVDwJG6k7PZEKkteszujP06cJf8Zqhq43F0rNsU=h4g@mail.gmail.com>
 <236a9788-8093-9876-a024-b0ad0d672c72@ghiti.fr> <CAK8P3a1+vSoEBqHPzj9S07B7h-Xuwvccpsh1pnn+1xJmS3UdbA@mail.gmail.com>
 <50109729-9a86-6b49-b608-dd5c8eb2d88e@ghiti.fr>
In-Reply-To: <50109729-9a86-6b49-b608-dd5c8eb2d88e@ghiti.fr>
From: Arnd Bergmann <arnd@arndb.de>
Date: Sat, 13 Mar 2021 23:34:59 +0100
X-Gmail-Original-Message-ID: <CAK8P3a1Nh4KUD85Fg_vFHf2fLMOqZThBgzyduLgfEtjGf-pm4g@mail.gmail.com>
Message-ID: <CAK8P3a1Nh4KUD85Fg_vFHf2fLMOqZThBgzyduLgfEtjGf-pm4g@mail.gmail.com>
Subject: Re: [PATCH 2/3] Documentation: riscv: Add documentation that
 describes the VM layout
To: Alexandre Ghiti <alex@ghiti.fr>
Cc: David Hildenbrand <david@redhat.com>, Jonathan Corbet <corbet@lwn.net>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-arch <linux-arch@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	Linus Walleij <linus.walleij@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:Cdps77GltlX92R8O5dW2CZmujY5wQCyjPlv7gszQbr7mWouid5+
 OZ8jclitxUjUzj0uULnW1wbbhVt1YUYwipsVunI3KlKmy0/A90pSdC2IqZona6SPU0VTWwe
 p00F1VMvZZtN8VeOi6X3t4nqAye24lofwA0Eh5Q268CoXZ63301/L7rAJ50O/dlCb4+//vu
 hOKYIuHJfZq50C65VA7rA==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:Axt4sV4Sl6s=:Bwm88MpzdAi+owt4pWcF3b
 Yuhiv9Bj0c3pie6WbUbMBMGi1Zotdog+683AlYnCghHjzSWgdGgCnK1n+gAO26ie06lY2HfQQ
 FwGJzbyARW3ldk74iFp+4fhuJP01ILQ8okQ/n1BEmGo7B4agWKtj4nk9N99nqVmzBErOQTTFN
 Afe1tt4ypo0hBagmYpzK4a+YSVFAm6ACbb6OiSWspdnnO3DoNyL/cpz/S6qm612DRxIPuWjtI
 w276IN+OSfviIUPjXQY3uIwn1cs3TRHypIEI+q+K3qx+PxoaCRson3kzldhlrnMe+Dtl/1kQR
 9+uZ0UTSJO5vLqyTb/eWx8pFoTJMlf0Kxc0m1c+YFV5ZINQkkJrW6j6nune8oQGNWRHqRl3jQ
 NGKV8oxynIY6Ibw+FC1LMNpMTcuSuIF80ZVzMF/q2MzIAhsfk1o3/vMFe43xB
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.17.24 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Sat, Mar 13, 2021 at 9:23 AM Alex Ghiti <alex@ghiti.fr> wrote:
>
> Yes I considered it...when you re-proposed it :) I'm not opposed to your
> solution in the vmalloc region but I can't find any advantage over the
> current solution, are there ? That would harmonize with Linus's work,
> but then we'd be quite different from x86 address space.
>
> And by the way, thanks for having suggested the current solution in a
> previous conversation :)

Ah, I really need to keep track better of what I already commented on...

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a1Nh4KUD85Fg_vFHf2fLMOqZThBgzyduLgfEtjGf-pm4g%40mail.gmail.com.
