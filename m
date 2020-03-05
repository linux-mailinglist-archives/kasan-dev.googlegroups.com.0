Return-Path: <kasan-dev+bncBC24VNFHTMIBBHNYQHZQKGQE4N7NDHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 17C58179DA4
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 02:55:42 +0100 (CET)
Received: by mail-vk1-xa38.google.com with SMTP id o189sf1438585vka.23
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Mar 2020 17:55:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583373341; cv=pass;
        d=google.com; s=arc-20160816;
        b=lED/GalvOTHyvru+8i43+O9Fa0e6mgXxbTy7R9WBWnTir4mFb6hDCbtdWBK82vFLK7
         qW1p1+INhheKO+HtYqg8b/Zik8E0mcsA5j17x3LVpqY2phSlvWqUcQXcmoqJa8841+dg
         MtBpd/fa+b9iUDNxs9UABWBz6ulDTjV0MTYZ0nNIVb2qm70HWNnFv+RFUwDPD+wu8gVn
         wDttEL7FfV+L18xfYadwUf8r+4wj9S0r1sIQY6KfKt43CL8Uo8X46YYPVhmx3NiNxZNW
         WWvJEKnE3GmjHjrnSC2qxwhIIfEod5LRGQmI6WCrlU75rpCZIl2fvbGO48ABADvl9oY3
         olAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :content-transfer-encoding:references:in-reply-to:message-id:date
         :subject:to:from:sender:dkim-signature;
        bh=0OjeU/nIPdStS5KdnVfhy50JFHvmspj0in9jXM4MeP8=;
        b=nv/e+GcNcS6suDeS7J13RORD/H4pEFbWniDSkfwyfTAE/MzbHKAIlCf5MPcpPdM6of
         sJA1cxZpKc4DkSS7gaVSjdYHYctOhjh2vojrhAPB3D/99XzjiJkaQVolyMz78VqT861A
         e0XTsH20OXw1Skeozr+lSEQ7h3Q7Ycs4tzph3FNUeBynRDo9i2cXm2NmQHm4tEmcwrOu
         FdqKozXPy0bfR6XhF5+wJA1BM5JDuXg0GOkcWIuzWNXmC4HWOz01g31CQ1bK2nbPaCrc
         L4L8ODgttzaK4h6pyALXIotJFWAHsbQt4WBXjISW69W6AR+0lvnE8KFyoh2XbnqeTDHu
         o53Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=azl9=4w=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=azL9=4W=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :content-transfer-encoding:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0OjeU/nIPdStS5KdnVfhy50JFHvmspj0in9jXM4MeP8=;
        b=Hx90ih37qR6u4FRvLem3Pi5wA8Gnx3OvBfqILIwvUHeoVmHxSmU1eLkcoAPAW1NNT4
         2uGnhO9Y2Sw51GU4ftgLR0qzKjylwb3PqoFDIjkeahWpWTzaY0Co2tXxXtefIbnrkPnM
         Zb26qt8umYGfksnHJlCNj5C5ySIKmD6W7Z8gCIppk+D0jAVgrf4uXu9YPujVmk6DLoxe
         t48QqZGwnXHdLzELYJ54cd6wWnr03ix6cGMavrXfUztZFQCSi9GILTcC+5B1+6F1sG8P
         6XPMO2yHS4YOxr+VdJnlzDWYmj5Nv+EoGSdisg9mHPvrp1Q5sr0s8d4fZVLh5qlGQ+zs
         M3hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:content-transfer-encoding:auto-submitted
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0OjeU/nIPdStS5KdnVfhy50JFHvmspj0in9jXM4MeP8=;
        b=fMQZ7P0tU2o86OW/cUFd+pQ1m6zsv2ptXHcGm0yjDlRAfi9sTPGvEKKlz1veoX4Vzc
         kOEzWJbrTQf9NANww3G5W24v+mQkeNsNBrxI5aWWoKMRpRbTWM70b7liIlDpbyXiDDwu
         BDhm5mUyOp+c5Geav1C9Qc0mcjSBmCSjgsWM67DOR5WxfVmqHOqXnlVk1iMHDJG62v5d
         7L67XZrTlfGfz8y8R5NyMr4D+KrH2H5dPCTyg1ukWq0CeRESj6mBN8vSMBgEgcs0uki6
         uROYaZ0zg5W9FQf9XO9Apf/uZ24xdKjvctQv8z9bXxUGdhGETiln0WMg0o8qFgZJfy5O
         InHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0xQau5sAse0pYRlWQVlFjjRHdBbEmjA5cQ3GSAOCidE6P4v/aq
	Z56GOhorE3WUmN3Zj/qN5M8=
X-Google-Smtp-Source: ADFU+vvdjsFYXQOBZa2aeAKrgZ2L9eeiI6f6xT7kN+xraoM6/Zpu911LBpqe3w9xHd81Z2QKwKKjEA==
X-Received: by 2002:a67:6345:: with SMTP id x66mr3713670vsb.178.1583373341089;
        Wed, 04 Mar 2020 17:55:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ea93:: with SMTP id f19ls64583vso.0.gmail; Wed, 04 Mar
 2020 17:55:40 -0800 (PST)
X-Received: by 2002:a05:6102:186:: with SMTP id r6mr3637217vsq.80.1583373340767;
        Wed, 04 Mar 2020 17:55:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583373340; cv=none;
        d=google.com; s=arc-20160816;
        b=A8bWUm1hWJqhRbrUEBPa9JZw3pj2OClJZg5F2mP+YkWExP8chMSlISRXJU8l3ScqJu
         86bfSCxpygtheDu2SZa4In8cATaGeLZd3DwBS0M5zKPxu348wr+mDDxFATubXtGA+TJY
         omLMcwLJjrjLPYHT9yY3IBz8FK2f3+27eWjA+6zf05+1UlSm99+I41srpDbJwxcEDe3E
         vbngOage6EJ/ma30SFJ8jk3xjK4C//x7ptuqXHHC22iDPKF5UsVrNK1o+0MqKrzv+427
         LwA8bzoEjcFwHybEhslCxvO7Y5DxzsXGfOeZVEJfeF/jv+gKZBdrtpbBIMRbV8sffCGv
         Wcxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=TYHjuUFK1QaAtbexFYgHI12q5vfyHRvwveYVikJ1Mo4=;
        b=qFi2bOgzA/V1hTTmxSmta8N4sXfd8ID6MzoRQeJcjV/zNhhn0x3R4Q8MHmJhmtMrC1
         Bt0N5qTGLuFYfszxXRFeqEgVrbCBF2HbFSgSFZYziFwpPrHjGYZn1uc3PwW/Uq91BKFe
         VTklQllV3T+7XZyEeKCHE/lff8Q5fk+gVsy0Xy+dqU2CsN6/ot9CSOoqUcY8+/nUZjxf
         fV0vFnmDpSSXxx2BojpvXKkFuW+RbxIlqgLicE81xENwvMlIbrpdbbThVh78nJ+PZrIk
         AwXX+7R/pOCAdjGymsb5a4KG5taRmBe4w3ykoEeXhOEmvBqS5rILbvjttgCzdq0W0clV
         xX7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=azl9=4w=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=azL9=4W=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o21si171629uaj.1.2020.03.04.17.55.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Mar 2020 17:55:40 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=azl9=4w=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206755] KASAN: some flags are gcc-isms, not understood by clang
Date: Thu, 05 Mar 2020 01:55:39 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: truhuan@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-206755-199747-ByNmxklOt8@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206755-199747@https.bugzilla.kernel.org/>
References: <bug-206755-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=azl9=4w=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=azL9=4W=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=3D206755

--- Comment #2 from Walter Wu (truhuan@gmail.com) ---
<bugzilla-daemon@bugzilla.kernel.org> =E6=96=BC 2020=E5=B9=B43=E6=9C=884=E6=
=97=A5 =E9=80=B1=E4=B8=89 =E4=B8=8B=E5=8D=888:31=E5=AF=AB=E9=81=93=EF=BC=9A

> https://bugzilla.kernel.org/show_bug.cgi?id=3D206755
>
> --- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
> On Wed, Mar 4, 2020 at 1:29 PM <bugzilla-daemon@bugzilla.kernel.org>
> wrote:
> >
> > https://bugzilla.kernel.org/show_bug.cgi?id=3D206755
> >
> >             Bug ID: 206755
> >            Summary: KASAN: some flags are gcc-isms, not understood by
> >                     clang
> >            Product: Memory Management
> >            Version: 2.5
> >     Kernel Version: ALL
> >           Hardware: All
> >                 OS: Linux
> >               Tree: Mainline
> >             Status: NEW
> >           Severity: enhancement
> >           Priority: P1
> >          Component: Sanitizers
> >           Assignee: mm_sanitizers@kernel-bugs.kernel.org
> >           Reporter: dvyukov@google.com
> >                 CC: kasan-dev@googlegroups.com
> >         Regression: No
> >
> > scripts/Makefile.kasan contains:
> >
> > CFLAGS_KASAN :=3D $(call cc-option, -fsanitize=3Dkernel-address \
> >                 -fasan-shadow-offset=3D$(KASAN_SHADOW_OFFSET) \
> >                 --param asan-stack=3D1 --param asan-globals=3D1 \
> >                 --param
> > asan-instrumentation-with-call-threshold=3D$(call_threshold))
> >
> > This --param is gcc-ism. Clang always had
> > asan-instrumentation-with-call-threshold flag, but it needs to be passe=
d
> with
> > -mllvm or something. The same for stack instrumentation.
> >
>

Hi  Dmitry,

If I understand right your meaning, it has fixed by newer Linux kernel.
https://github.com/torvalds/linux/blob/master/scripts/Makefile.kasan

below the code determine the whether it is gcc or clang parameter. it
should not always pass --param.
---
cc-param =3D $(call cc-option, -mllvm -$(1), $(call cc-option, --param $(1)=
))

...
$(call cc-param,asan-instrumentation-with-call-threshold=3D$(call_threshold=
))


Walter


> > There is an interesting story with -fasan-shadow-offset. Clang does not
> > understand it as well, it has asan-mapping-offset instead. However the
> value
> > hardcoded in clang just happens to be the right one (for now... and for
> > x86_64).
> >
> > --
> > You are receiving this mail because:
> > You are on the CC list for the bug.
>
> +clang-built-linux@
>
> --
> You are receiving this mail because:
> You are on the CC list for the bug.
>
> --
> You received this message because you are subscribed to the Google Groups
> "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an
> email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit
>
> https://groups.google.com/d/msgid/kasan-dev/bug-206755-199747-TEol21KlYa%=
40https.bugzilla.kernel.org/
> .
>

--=20
You are receiving this mail because:
You are on the CC list for the bug.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/bug-206755-199747-ByNmxklOt8%40https.bugzilla.kernel.org/.
