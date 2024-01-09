Return-Path: <kasan-dev+bncBDW2JDUY5AORBLUL66WAMGQEHERD6EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A2F1828F81
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jan 2024 23:16:16 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-336f83b47fbsf2256649f8f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 14:16:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704838575; cv=pass;
        d=google.com; s=arc-20160816;
        b=jQCf3NLoz4BJRsxkUxmXKv3PtcBGykAoE58pcisgBU16O0P4raeHZqTbhCJtfdfaza
         ckiDRqQSXPJiaVwek3+/5q3l4azsdEMo0Nvp8HF8g3JtPHk1+ymlcoEjYOQd4i5d9B6z
         d5No9tVygqCFsqg1Y9GPCv7fWe+CljZQnNxuw9CE/OVXBuPZxUF/HiKH/PeUcWrV8TkV
         DRWppeHeFpf2Z7ypuatnArnHqlpOclQ15NlENOrN0yDrkoWX2k7gE9rnSCvdc0HC7PaK
         f5ZEG92fLycvpw38wFAoDjz2PCzSn0IFJXZ0xQMavqhqmO67fdZH0cLgUr7xLGwLEzml
         MnkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=aP6qMWs5fB6U8pd9V6BOyGiyV+4+1EwozZ5m+Sw4kPo=;
        fh=u5+EaDF7rLnyvi4dhfx+aOW5CjVIS0IejV/JZ59Fd+I=;
        b=A7q522VPdXacL205qOJ2H40KziRebXugVTAPA/kOoBYEAx8Q0x8xzYWBMrmginGf9U
         eniZuu1xwiYcdRmIvoun/d7wcZjP02n2VBhWKT0eBd7kfN/mN7JeHGVO4GSSWZWU6yEU
         xCSxNbpelGqTXe9Yw8+qizcKuRHq/Mh/88UIG1jQK8/lDzlp5F8OHCZBH0KIPMwCvVfk
         1uQG3y2ZwVcNZb0GghmAIN0ss18S7Z4OL79Lux/DFuR3G4eDwsdR5ujoLrrO+RpwmYkY
         O8aNOhLz9ZhgNDBlMI4xkx+zfpRkhVcDcF4r2JCsjHd6u6ayu8/nq6sP/Fhodrq7fWOa
         8ZTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cTzmD5yL;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704838575; x=1705443375; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=aP6qMWs5fB6U8pd9V6BOyGiyV+4+1EwozZ5m+Sw4kPo=;
        b=YYZ1o43G6XKpUKtmJkGCcWxEvXOSTl3tp/n8ygb/u+FrB2MLGIxjY9jXnaL7KgAxMD
         oKzB78CStBhPbAvufeNLImLQbI3FlcWazMvsnxeNL0zCUevQnByS/jznSFHbsaSGeaut
         wa8KFMqFMsoXiJ7lwubJvGzVw6Irl0dw8gjTBGPakvxozJwDFI8a6Xkyw/ysoNnIpD3X
         aT6VGHtnF2Sp7i2PYOoeUW9OmwiVkyw4Woz198RZcn+a4UrsagQZBrIkULbSWyNVQYfs
         evJAPjlnGRPhpWrc58X0ga7Fk7ajKi43I1X2VQVCTn/NI/HAtD8gYnXd/PUHh1KPdfrR
         eYlA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1704838575; x=1705443375; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aP6qMWs5fB6U8pd9V6BOyGiyV+4+1EwozZ5m+Sw4kPo=;
        b=DpKQ3iAAoooHQOSMj8n5lWaSwVt+8d/vmixwJ+2yArNLJESS6pxQ8WgxGi2DZLlTkI
         9781GcWOWtpkKWsksJRSTcWQGQRR3q5EE/2XRoWaktiTjBowt+nvTni92Nn0feLX/2mT
         5c012ZGjYaDl6mHkh1OHsPBi6MkQ6EYfFgCW9XUUzbwSFh59DEewfNJXX9n/xuxQoLl0
         vgkRaNaQP/Rkvyg/YSfecVnbViwzfiuQ78T+ebDi/71Q6kK80EV1UaObfd2Z8Hj/dOH+
         Xfc5hvsWKdTNPzWwcLHiR9OAUBtRl3vKQuJUyFseSqu6TAmg56QYIDQqN1H2v0Q5GGJD
         452Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704838575; x=1705443375;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aP6qMWs5fB6U8pd9V6BOyGiyV+4+1EwozZ5m+Sw4kPo=;
        b=hicHLKHseJO6ErF+sHcCOEtYRbKejCQPUgVuOx2Mj4Qdp58JrlKLxFnV0EBPrTVfCJ
         +FXY6zv2/mUxkAI/8TA6xvNPgSQ6k1CXm0IwV0FuqNFa2utr6c29wtlPKuBElL3ewdt6
         wsYRTe3nsZEn4ZdPLzP5sYpqc822ZAN+eH/BD81SSFEGx7YPUHcqilWN7vAIA+Pg7WTY
         I8cK4jGuPDHG54vubBxIYb6DFex75q4DoGvz+lkGsiVEaMGulUhLNQk+LiTCd6oEa0hJ
         mPa7d2NYNL/PjZeV4eO+8BzIY35si6DGhCkoGAbo5Z3wGiQZuk55fiQYlqlshrZz/yl4
         egmQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxQ639wNcZjzsKe1vcR9l8ygHBJznqJovrn/rQGua/rYqh4b4FA
	T1CrF+EPDU5Vjkjto6aQKHY=
X-Google-Smtp-Source: AGHT+IGp7z8nFv0VylCz2MVbfnXAbq4X4XSPr4U3u1/2SsfHYq2JhmBuqaah42WS8HLllKVLHfJx4w==
X-Received: by 2002:a5d:5d09:0:b0:336:5e76:e51f with SMTP id ch9-20020a5d5d09000000b003365e76e51fmr14133wrb.7.1704838574919;
        Tue, 09 Jan 2024 14:16:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:701:b0:337:77fd:9cfc with SMTP id
 bs1-20020a056000070100b0033777fd9cfcls487786wrb.2.-pod-prod-08-eu; Tue, 09
 Jan 2024 14:16:13 -0800 (PST)
X-Received: by 2002:adf:ea10:0:b0:336:78af:122e with SMTP id q16-20020adfea10000000b0033678af122emr5767wrm.199.1704838573220;
        Tue, 09 Jan 2024 14:16:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704838573; cv=none;
        d=google.com; s=arc-20160816;
        b=v898KIRN5zmjbNFLrOtM6Dm0C2jItysDcwknQC1O7PYFtf8qaFuNMoZ+X+QuyqFXP+
         BeVi48kQ7esgsOMz8jXPWt1OfGh4SN2eW+AuDwJZn5D/DJNGbYpaC7uGaexqPdU+J9Ya
         w8JwIYjS3mdIopzdnTuMqDz8QFMEIkHF8BHJRqxeKvzj/p4r9TjrqzpZWMOS0olbNEAo
         RskM0y8AxqFUl0wUaj5XudsdiEkHWeg901ib0uJ/31RDTFSMvFvhDg4rC/nUSZmRA9yF
         gQjmUES9wsrXSwQQdFJYPI0iNTgAOXf/pqXr2T9NGc9EaL5to57Sxqq/HEgVU7ocevsi
         1MmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=MixBUBxVsBGX2GWEWX3K+n4VoV5LO1ISSw5Nn8Xv6uU=;
        fh=u5+EaDF7rLnyvi4dhfx+aOW5CjVIS0IejV/JZ59Fd+I=;
        b=mdZjEiZ0BIBRy4hvFd4R3/U0g1X4S83+7/OyKQ3kwy2aRd8Hgx5d9SS+dvVeI+lTJ4
         q7HJzaOeneOjy78FjFwxYGFQx7zM1qNTQg2COlP2PeyY5iGj/ubVaTFz9moK9i8vx7C4
         nAm6xEuBZnKn6zSfU2lFkaWzcZygbYGLBE+rNBSSTvhlfwMxVRlcQk2eJfCypfe22oa0
         IKuDlpuXWb+F8Y39Oxjy2AwzOxRg5A6cRJyAJidhbXjNhGtQ174ifIO1i/eCCJH5TVIp
         S2JdkUZ8NmlfjOMMaCQSZNanIeyyAvxF96VeXEz3UiiugqviWs+F/P7EHAm8pr6PV9H8
         9MxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cTzmD5yL;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id w11-20020a056402070b00b0055410f019ccsi109476edx.2.2024.01.09.14.16.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Jan 2024 14:16:13 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-40e47d74824so23549625e9.2
        for <kasan-dev@googlegroups.com>; Tue, 09 Jan 2024 14:16:13 -0800 (PST)
X-Received: by 2002:a05:600c:3849:b0:40d:9877:ceef with SMTP id
 s9-20020a05600c384900b0040d9877ceefmr3473wmr.60.1704838572674; Tue, 09 Jan
 2024 14:16:12 -0800 (PST)
MIME-Version: 1.0
References: <5cc0f83c-e1d6-45c5-be89-9b86746fe731@paulmck-laptop>
 <20240109155127.54gsm6r67brdev4l@revolver> <CA+fCnZewUEv2BMX-D=a+5wosusM-H3tOBpeJe6oyu51mMLXQnA@mail.gmail.com>
 <3c1213bf-783b-49de-b012-00494e7e991c@paulmck-laptop>
In-Reply-To: <3c1213bf-783b-49de-b012-00494e7e991c@paulmck-laptop>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 9 Jan 2024 23:16:01 +0100
Message-ID: <CA+fCnZddAhB+T8L0g4tcYoj0QMvhqcA75ZPM_kqiAEDBmLzpHw@mail.gmail.com>
Subject: Re: [BUG] KASAN "INFO: trying to register non-static key"
To: paulmck@kernel.org
Cc: "Liam R. Howlett" <Liam.Howlett@oracle.com>, sfr@canb.auug.org.au, 
	linux-next@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cTzmD5yL;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332
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

On Tue, Jan 9, 2024 at 6:20=E2=80=AFPM Paul E. McKenney <paulmck@kernel.org=
> wrote:
>
> Thank you!
>
> But no joy, please see below.

I reproduced the issue and just sent the patch that fixes it for me.
Please let me know if the patch doesn't work for you.

Thank you for the report!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZddAhB%2BT8L0g4tcYoj0QMvhqcA75ZPM_kqiAEDBmLzpHw%40mail.gm=
ail.com.
