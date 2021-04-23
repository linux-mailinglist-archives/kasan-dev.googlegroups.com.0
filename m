Return-Path: <kasan-dev+bncBCL5PDOG5IGBBTGFROCAMGQEVU5LN3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AD983695A0
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Apr 2021 17:07:58 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id r20-20020a0568080ab4b0290186e76a5ddasf8129183oij.21
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Apr 2021 08:07:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619190477; cv=pass;
        d=google.com; s=arc-20160816;
        b=ImQdwhNxdfzUbqbVDfb8mVH3IY1Iq2RZ+8+5NiDphLOsnGPNbY0DrjehqwS5vC9zLD
         zLAI83Uobs+ZF7t+c1v6dzDTCWR+PwWyx6fHEExKPVhUAPPtoUmaPx/Yy4QCknKFpSic
         P1SeplGB19oM3KdzRGLUQ444En1llubMI8C7ktVHlvh1tCWFv1HG/k6ja6qgp09mSK4o
         PHVEjuQGtBw7ZJxQc8xZGd7yVBeS8ovRxk0fABK4cot1LgHrRRhsB27QmHLqN7pxjeJ0
         WsZGUDjpHKLs4yS5yLVln1ktHE0JGljuRrhEy20FdR0pTpgSosCtjzD5mETvm9+31Ih6
         NVgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=q7mZle+D1SmznnBCnUgGNQFm+nrFRv0qtkd7EEuB+lA=;
        b=GjXxOodhxZRJPyS2NJVlXCWUbeMpGOoBYhE599FPhDOL2Fqo0RT8CJihRj1em5G9K3
         kOfDVOkRQyYs9xkceG4X0R3ObJDFORJVUY9v3a5SzeaMhlQ2UIuAN028JHa69imETFGv
         t7ycbh+5uS13io0eQj92xsq4txsDwIlmEzMrivhFALawjB8FFfBz33wc+MAD+eZGIxSf
         neDvlOKuAq78Wt9ZzLHYvIxOqfMk1ucZPSSsj8IjRRtGI1i8Bgs1aYFkNLZn/9JWCLnd
         gFk7avzDIXxSJAedhMt3zE+x0S+bUB+s1BgmgXB5bPFEaJ4hz9obzUWTAW4xMl498d60
         /Avw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=JfgSuE10;
       spf=pass (google.com: domain of ff4792715@gmail.com designates 2607:f8b0:4864:20::932 as permitted sender) smtp.mailfrom=ff4792715@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q7mZle+D1SmznnBCnUgGNQFm+nrFRv0qtkd7EEuB+lA=;
        b=Zn4IoWn0GLCzf0/mVha3IAT2uNC+BR5HrG3M1XDrbjCsAIUwtB9f6WB6+r9T4Ja5oC
         GGognsPJP+04kNYeX5NyaKrJJ68UVYNrcwKE2b9Kwx2YnnA99z2L4v87UkF0XdjRIHBR
         oCBJ7VwgPPgDqhTgVWT1VNx0PqnpAr5egb31BkWu3EB19W8tOaTDFIbNbwWi/fAis6po
         +Vi2u+9KDTjLTInsQsQrlYgV58sNHhu4GCKpy8Q9RlHVM8C1KAnYdku9ud5hP7MydT2E
         CJUoejW++X5TBByY3ctR7hPxLpRgJpsgz+N/7XCVhZqXhI/8v7bOwKWmZ1Xclle5gpcG
         DY3Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=q7mZle+D1SmznnBCnUgGNQFm+nrFRv0qtkd7EEuB+lA=;
        b=uSmdT/QtP0KJIfXUcyLAqH125/dz93KvYx9cp3QE+yCRNgm0q+Ko+wjlq4QxJ3lmcC
         EmSWQKl1k21kQGxEB0Hq46RDEpSyeyxD6KrxC5PughvCBQa3U8+tylQEFBBXKGU9Sznk
         KO+lyxNanG4AjC1rRHyYuMK/IIanP3buJms6k7WU4uQjC4fEligIKhhSsE2W3aVcTPDZ
         T9fSjXjN3BwzdD1UXXUBjOhgqQcrIhXiL1Y8RZyWuOv74jewjUq+pO+oTRJTBZHOmLNQ
         6e1upyad5535g+vtOPaLcxdhalz2kPq4uslx3+dpg4IbHMPiMxac61OeeqKAyVqDALhg
         jWoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=q7mZle+D1SmznnBCnUgGNQFm+nrFRv0qtkd7EEuB+lA=;
        b=ULzwHVVvyYFNbpQBgEJP4jh/Z3Yj9hLHNNvxL5MsDOjcQn4KqZ6ppeIbwD7DElHi/n
         VMDNG9iv5t2ZrI5EC4VhVJQ0Fslw7+mns1cBOPtwU2gjNaNeqbVQDGuY7bb3pznLDO5g
         BXGx4BOB3nA2wxO0wQa9Rsy6O7peHn9XxHo5O2WqERWLf19PwqTCmgfoYsU94qGd2CEW
         MJuuic68NsqbA2oIglshbnvjmY6jhONDTVso+TmA4Le/7tV0zYDWleoFudC9HX2TpOfN
         JOGbYGfLDpezG5vWCWepUMIrjK21KvQk5guZYZrf6Amb4GssbfRhEEYvaOo91AWMl3m/
         zGnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532n8wf5UIgWx80n0m68xARJznPZT1GY4YmCW+xLRY6/yQTy6U3T
	w/H5sUMqqSXG2oMCImujCCg=
X-Google-Smtp-Source: ABdhPJzubtmREgkXFEMfShCXI4oh/VVaJkPOaZM+OhIQ8MTWM+Y4VRMkRuuiuw7hUcm4KwoaPXPyww==
X-Received: by 2002:aca:bc89:: with SMTP id m131mr3182527oif.71.1619190476938;
        Fri, 23 Apr 2021 08:07:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4b11:: with SMTP id q17ls2908473otf.10.gmail; Fri, 23
 Apr 2021 08:07:56 -0700 (PDT)
X-Received: by 2002:a05:6830:15cc:: with SMTP id j12mr3782244otr.274.1619190476603;
        Fri, 23 Apr 2021 08:07:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619190476; cv=none;
        d=google.com; s=arc-20160816;
        b=VwBCljTwQ7AuweRZebxubDl073ocROkbfr/MyOADC7+tChuFWSt3m5P7Li5bHF41WN
         5TuDtDFpWs0E1N25mOGt+se6p815CLcMTgzPsbUPWy1amya4gBVXAi56TDFFyhXVTqHJ
         o08DEbYMfN76v1L0csDlTB7gQoXFqi/Qmhp1tWiGXj9oBi4t9lYT0MxFGReSHzg4qv2Q
         bohqXP8QYwV7YD59phUJRz8o38C6qgbzLLgZLMxGVZBTNeM+q0zWGtrRHvgPZm7HjUS+
         zzgUIec8rbkCkeBlis0Up8+irETDXntaAF6eeIB963lll5WpX4BuPtOEAbpaLQUoPNSy
         Ll3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=yydVf0/+KDE8ylCUYEaAOgQiPYknajQEU6aabDPUHvo=;
        b=QaYj6tt+FwCYNNA9YCm7vu49wwhgZIn7cJezkPJDMhzPUh7VAgkyiTmkBogPO/osRc
         h8NsWKGn+nGOOyvOPjnhiEcUupV1OPJhQFI0hYiH+blTLRpnl51xLeOgQ3oJr8eEJ9ET
         mdIA9o2kfbL3J3+XfvbmhjgYR7uPsxJhbpbxSrqnA96qLB8NOiYNbf7DFUn4UAnyZcms
         t5K5urPcYMYowmjvfZ8r3wE3bzcznY6gkS+5ghBSbZi+9XzYJrSkYDP4zNx+OcrNj6V8
         MRyhT0Ol3yWv94Tjw5ShnPEDtliJ5S5Vtlnv1Bm+vGnSWq2+UBrKiBICCCwMuOLxxfrc
         M2Vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=JfgSuE10;
       spf=pass (google.com: domain of ff4792715@gmail.com designates 2607:f8b0:4864:20::932 as permitted sender) smtp.mailfrom=ff4792715@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ua1-x932.google.com (mail-ua1-x932.google.com. [2607:f8b0:4864:20::932])
        by gmr-mx.google.com with ESMTPS id w4si566789oiv.4.2021.04.23.08.07.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Apr 2021 08:07:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of ff4792715@gmail.com designates 2607:f8b0:4864:20::932 as permitted sender) client-ip=2607:f8b0:4864:20::932;
Received: by mail-ua1-x932.google.com with SMTP id r1so3336466uat.4
        for <kasan-dev@googlegroups.com>; Fri, 23 Apr 2021 08:07:56 -0700 (PDT)
X-Received: by 2002:ab0:30a6:: with SMTP id b6mr3668039uam.44.1619190476202;
 Fri, 23 Apr 2021 08:07:56 -0700 (PDT)
MIME-Version: 1.0
From: Karen J Brown <karen.j.brown211@gmail.com>
Date: Fri, 23 Apr 2021 15:07:44 +0000
Message-ID: <CAFo-Wenawb7RB4axvMu0g0rAthjwm4-3SxdNbVEyYQDMyp87ag@mail.gmail.com>
Subject: 
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000002866a805c0a52985"
X-Original-Sender: karen.j.brown211@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=JfgSuE10;       spf=pass
 (google.com: domain of ff4792715@gmail.com designates 2607:f8b0:4864:20::932
 as permitted sender) smtp.mailfrom=ff4792715@gmail.com;       dmarc=pass
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

--0000000000002866a805c0a52985
Content-Type: text/plain; charset="UTF-8"

 Can we talk please ???

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFo-Wenawb7RB4axvMu0g0rAthjwm4-3SxdNbVEyYQDMyp87ag%40mail.gmail.com.

--0000000000002866a805c0a52985
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">



















Can we talk please ???







































</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAFo-Wenawb7RB4axvMu0g0rAthjwm4-3SxdNbVEyYQDMyp87ag%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CAFo-Wenawb7RB4axvMu0g0rAthjwm4-3SxdNbVEyYQDMyp87ag=
%40mail.gmail.com</a>.<br />

--0000000000002866a805c0a52985--
