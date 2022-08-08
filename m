Return-Path: <kasan-dev+bncBD62HPNPX4ERB5OKYWLQMGQEUTUDXRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id A993A58CE99
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Aug 2022 21:35:19 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id a19-20020aa780d3000000b0052bccd363f8sf4192260pfn.22
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Aug 2022 12:35:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659987318; cv=pass;
        d=google.com; s=arc-20160816;
        b=eqTpaSIlI3Aoi4GuG6s27E71Mfm2rtgH8Qd5YuEQyCRPE8NXG2TQFky8P7QvFiPN1E
         DwG9eHB4UJ5MK4ZywNHVv5Yj2Vvlg3FnSYoIXpCsIw9nsbulRzTy7i/MVrJBg3j3YHbR
         irLxpX7cQZKrAU4Yd3FklaDVL2HCBg6K17DlSJHlNuW5zGFBI5SNgDgwvo/27DuuvVYx
         UfGUA3Tws0VUI7t51usKM2P0NO19keiW9d39gteRtgEkaLtFVQPOVWdsfLzUdSxskok0
         IS62509YayXr+plRlhw1qgKKj/mCTyRSDCg/W3sSW3MvgeFKYQWE4l6CEL4aSzVh9kHV
         N9Kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=cGmjx7i+vaFJHIQwO8aOdLk6bfaM0W88Vj6/mNnwXfA=;
        b=AgZzIGMZIT5UFXS/LXt12fU//nmmxMCDZqyifyd7syAIHHdsy12yBYa8wtqavrGF5E
         M7N1Ufeb1S0MnIqh/gJ6Q+n0nQYkWN+T0hAabzh8BLMFs8wFaH+TptXVb+jsBHSboi1J
         4/JR1I+WuDQv4ieI+g5Q805Lo9PjFb/83MDyU93HW78NXuJMz/HjoLUINcoeTLt2X9bt
         Rxb5vEU55yBCVb4pfQrfaiH8eczyE2khRK9uMl2EQ14nyfg/Zvj5ZDbHfirFxRCbC4FW
         3/EnQfLC5fmI18fKbmTP+nJIdCrFqotXtSiW+e52WtRzde8kZuRW4sNj6leOA8fLXpYw
         WQ7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=anh3s+Ri;
       spf=pass (google.com: domain of williamsjeff277@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=williamsjeff277@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc;
        bh=cGmjx7i+vaFJHIQwO8aOdLk6bfaM0W88Vj6/mNnwXfA=;
        b=uBuVjqOedNAhPN3at0Ntaf8P819pbeyuPVuhJTr9JcqavMM8lYdUOcUUeazfUdPYQB
         dKuFURzPQ6VjX4O4Q+cNfjHir+8sn9oT1RRa0/uVWuH3iwjBJJaiDYRAmB8nN0taRWIZ
         ZElDm08LKDoEZC62qJALkkYra2vx84oyaFFICyW/HwLVMb3ahPmnEFlkhw2Mr2/mfNpn
         5CO9nH6ezAKIZ/23tQGcpP959Xqm0RK8TOtb/EYbKpVzIxR3CbU3MlY72jC98fjZVuzZ
         HQzNKo2zFE059NmHTWtl345HXyd8EWfFrY3YhsTHh02HMAKINHnVm/zRKA6lK2+NrjxY
         O6wg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc;
        bh=cGmjx7i+vaFJHIQwO8aOdLk6bfaM0W88Vj6/mNnwXfA=;
        b=HnAtl5YHkssrGMniJjaYFnhzoZWJRazyZ1ykSM6WbgnLkA476F5OoN2Brm/x8KfC2H
         cJCb/LpxikthDUOeuKRgQRJCZ62D6brUWC+3j7Pc/N1VeTzzC7IX4yLtEa48E61njmrj
         lsAzfo1yh+nPdLSe/H7kQu2z1H+5sncrwo2VJnTJEuTRpIMGcnQA/+OlQk6z4cummouQ
         +jkJ8aSgIDuUvgiQLwe6MrbvzgEUqPvfDwDX7zEZ73NykP8vEFwrOyXCKXHBxE0jrW0K
         Oh7tuzl8R7ldsj+wPSTeQUG3h+tj7AXaj82IluLO1nlINEB9eWLCupDAT/dd4+kA3/fJ
         sIVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-gm-message-state:sender:from:to
         :cc;
        bh=cGmjx7i+vaFJHIQwO8aOdLk6bfaM0W88Vj6/mNnwXfA=;
        b=viQR6y5E/9qrOZBFV901qH2Fv3u1nRy/i15ah0uH6zMzIe7kCeDJMm83SobQedVakz
         5IjPi4CSHI8KTq0+xwgnz+7J7Yo1RFbRFGbWawUkx6c5GGzVbRWiLn5I9ddZx8jL9v8e
         IFF22zTzamGsLpUKmaJk9ltjEuoxcuFidHN8SiHx+utFYrylZNjX1mSPdt2FqYanxLi9
         mugnmGBP/BmB3O6RBmRRqe5M4Ln+CpXxIDK4fSSTVHGW34o1/8FETQ6nU4koRJwg9L7+
         3NwjmEB70S0/Ulm+nT7XFosKxdNAvFenCTrlep6pu3d5ujxSQTilDJWBi+XPvgGZvV86
         J+rw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0QfF2gM1xxbevOl+YKFVRnV1wJ9sbtk29eBHuQ/Gx6Ekvqgkgd
	kMmsUVI2M6ffhFLLG8iFryw=
X-Google-Smtp-Source: AA6agR6Kh58YOXrebVE5tQ2Jtg/sOBZ7dVUCbpeWJ2OUxwKnhE8vdo8Jvo1Y9wZ9FrVGutfYhpolZA==
X-Received: by 2002:a63:5916:0:b0:41d:2c8c:7492 with SMTP id n22-20020a635916000000b0041d2c8c7492mr10527016pgb.81.1659987317872;
        Mon, 08 Aug 2022 12:35:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6906:0:b0:41d:6d38:1d40 with SMTP id e6-20020a636906000000b0041d6d381d40ls1972536pgc.7.-pod-prod-gmail;
 Mon, 08 Aug 2022 12:35:17 -0700 (PDT)
X-Received: by 2002:a63:e018:0:b0:41d:ad3b:26e8 with SMTP id e24-20020a63e018000000b0041dad3b26e8mr2144771pgh.528.1659987317143;
        Mon, 08 Aug 2022 12:35:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659987317; cv=none;
        d=google.com; s=arc-20160816;
        b=FAxjvHMzqv3Ts3G3cEPpGMrdSBdMXxTG5i1tvwU8fS6Th2WhDL1iHOc7URFfdWAqgA
         mmpVGA89DFqpkYmWYHwxKW1yuF6EuumnfeYEGzu/420IPWLv/6TWPKGHg8PWxdNq9kDF
         YsJvedWsyTZRm+W5QNhYknb5CPxYYYfXG8USEyRADU2FQgjvk5oL0BHHhIvqVPUHLMhV
         /zpuZKdiq2h+piFH9TXV7XMxIIY2upFXrQU2KdvNa+O+nTJ1uC9m5RgsL3IQyYAtmctq
         TwthfWhL02cZYfkqS7TeRepqpHF71DJzZmNASr3JG6hXLMq8YDORtkeaa8eAWSqNnXhC
         MnYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=nq4ZqtCpAaXlFDG4YdM95TTdNQZ/Qvs7LWsbwbw6Xvc=;
        b=yMyEmEznsDSZtUo885ZEeYs+jSk3cQtObEXa1RB6jxUS883q66FrwZYxvfxYjg87Ce
         n+8ddjdQ+GUk0iGv29SuAFg85LJwQbO4ZAQbx8+8NTVAJB1B2grU7L+/bNb/Qa9zVM8y
         0BLpoNaQS3r2zAd8eWzOPPpz1oxG5G22NVBpBHCABkSbg6yJ+1TLLEuRIjwKcbU+z72e
         IRB+O+5hYg+R+jeeyJnI5yVJr4Sh4ZETCGlmhcD0e4Q6BVZB5PXAAt6bD4ZCTtHncXgl
         mjgPwc9mKrPerHGGr6rTV0SLdiI0ShWHI4pUvyBAfSRmKpHHHWlcV4n1cCwDPLOBM0be
         /lhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=anh3s+Ri;
       spf=pass (google.com: domain of williamsjeff277@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=williamsjeff277@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id u18-20020a170902e5d200b0016d5881a19dsi399908plf.2.2022.08.08.12.35.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Aug 2022 12:35:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of williamsjeff277@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id d65-20020a17090a6f4700b001f303a97b14so10129275pjk.1
        for <kasan-dev@googlegroups.com>; Mon, 08 Aug 2022 12:35:17 -0700 (PDT)
X-Received: by 2002:a17:902:8f8b:b0:16f:25c0:a54d with SMTP id
 z11-20020a1709028f8b00b0016f25c0a54dmr19177085plo.153.1659987316539; Mon, 08
 Aug 2022 12:35:16 -0700 (PDT)
MIME-Version: 1.0
From: Jeff Williams <williamsjeff277@gmail.com>
Date: Mon, 8 Aug 2022 12:34:34 -0700
Message-ID: <CAJE-Q1sP9fo8ZbYNNaAHYyWEWYDx8Z+oi38oDqRmYyvSO9+s8w@mail.gmail.com>
Subject: hello
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="00000000000055861a05e5bfea02"
X-Original-Sender: williamsjeff277@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=anh3s+Ri;       spf=pass
 (google.com: domain of williamsjeff277@gmail.com designates
 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=williamsjeff277@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--00000000000055861a05e5bfea02
Content-Type: text/plain; charset="UTF-8"

Hello,how are you doing today? Did you receive my message?

Jeff

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJE-Q1sP9fo8ZbYNNaAHYyWEWYDx8Z%2Boi38oDqRmYyvSO9%2Bs8w%40mail.gmail.com.

--00000000000055861a05e5bfea02
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div>Hello,how are you doing today? Did you receive my mes=
sage?</div><div><br></div><div>Jeff<br></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAJE-Q1sP9fo8ZbYNNaAHYyWEWYDx8Z%2Boi38oDqRmYyvSO9%2Bs8=
w%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAJE-Q1sP9fo8ZbYNNaAHYyWEWYDx8Z%2Boi38oDqRmYyvS=
O9%2Bs8w%40mail.gmail.com</a>.<br />

--00000000000055861a05e5bfea02--
