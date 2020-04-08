Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBMEEXH2AKGQENFRMYWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C93C1A2B17
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Apr 2020 23:29:21 +0200 (CEST)
Received: by mail-ua1-x939.google.com with SMTP id d2sf3220658uak.11
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Apr 2020 14:29:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586381360; cv=pass;
        d=google.com; s=arc-20160816;
        b=iVKWHcwWmFG05TUZWQ73GwE04vj4Jl1utlU9Z+9vSuLAXQwQ0Nc3WgoI6qvYZdUmQS
         I4Za/SbefxASKnhCi0IDOtjGeofFJCbDyxuZSxmCc36QdZBSJXowyNFPEzep01X+ADNP
         hY2e4fmYn9cqQ3Ji19UregPFluPIgKa4FCFYFVAPBEQa6TmzLqFiAktlSdDv5FEEgqRA
         AIY1qMDOZeXloH1BVV1S88xlAIBfUiSn/IYnO65NkEq6vnxOifrir5bQQNNO/PbrbTzT
         9UZpH7xFxJN99gfVoXSH9cxZHyeFQCN3CzIbFuPPx7xmm1cYQtwIotthx8GmbR4Rx31J
         AVEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=jW2v8a/ibGG43bFsIFUIJubfOwGkX/5a+bo6UcXWvV8=;
        b=vIXfXhCEAjSGTpHr63Wst8VSXbkb42v5tiFuxgSLt8kV4C33/U/O9XHFEBs3Jl4bl8
         4Y50V/ls4gg+pmveBsUFsYPHF93bJZ1TDRdVJzati87fWLRI0SafxVPFgtRHt9nbXarG
         CIm93Mi0Mjc5xh7oTn5rwYW3ssJXPCR7E+IAb77tj3VklfWKWFavFUQF/rCL4HOC4vlW
         dPYdiX2P5kRSX/7nZCKkt2DfR7vTdNTLZJXJyWerR8R3TGK/m8qOHV0RAiqWNgLDsDN9
         gyXuRMZCg3W9MSspdF9nRflDQC/DEAtCrrH1hvYTZExZrzhWuyuSsLiBuFCdKOy9mcok
         Piqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=BWwwyhWd;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jW2v8a/ibGG43bFsIFUIJubfOwGkX/5a+bo6UcXWvV8=;
        b=Jzib5FJk5j/+ok8f79r9mM393qg0gT736fuJ4RMVNeQajfzKHaUiKTm5e0El3w1lmR
         9QQoQKIHDC9V38O6lyrmUZcw8q26SMrkeXL4TMge+Gi4+V6ABjEKEZj9TDdRULgUic/4
         YnqakYdcD4Q5kbiXu+So4of8UM3k8pbYiR81wJ7omwXx0YxWC4aBTDCd+8lJOWusrEYh
         7McP1tdVQSRHx7FdJNIYJHy0Fs5EnTbBAIc/0WGvS5DmKbWtqlokNh6qSGJXXtpxO77b
         GmKx/N8cD4KBWvjIMn9qNDFXJeG6vJgqBd+2jPLrLIk8vxpHWQ63zwNEx4ZFu7gBm+S4
         rjkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jW2v8a/ibGG43bFsIFUIJubfOwGkX/5a+bo6UcXWvV8=;
        b=cGOUS6byOewsLmGFMqYJ2jBY9rVrSctKOJXYWp6iKvpvSH245n/gD1c1KW+hoWcNqh
         GLftR9nTY0nXykAN6tdTnrfAMZyNUn0jPd5+C5qQyHwSCgoyftFyn5oM9dciAMAXhBfc
         krxpQl30b2YapLfPBjIpIDEUVd7j/uw7Znov95Lbg5dTX2oPsY5ou57yYdZPd6G4PZu1
         awdZV+aVWsimQmmonarrCXQfofBPQTfZFQd3aVOC1nBb4E4KSBVCA8HwxkBQOj2fIeMP
         FFAlirOT6sbgDbMkKgVaUwAKLCvgzB3Qlc6yivf9K32gJHdSFkvHl1diEeq+LgLAN0m+
         e1rw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZdQpTKCaDMlrimoENFjXTeBo/36X/z82B8BsOIyQuZDYJO/DVS
	v2bhDNL6zFv+K6b7RdY929Y=
X-Google-Smtp-Source: APiQypImRG4pcJLtpbQRWDKZJuheAK0xfZhOio6M0xfFicTe3HDn+Swumu8ffmIJWwlXEIdjv51WUA==
X-Received: by 2002:a05:6102:2087:: with SMTP id h7mr8312978vsr.226.1586381360564;
        Wed, 08 Apr 2020 14:29:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9acd:: with SMTP id c196ls503112vke.6.gmail; Wed, 08 Apr
 2020 14:29:20 -0700 (PDT)
X-Received: by 2002:a1f:a090:: with SMTP id j138mr7190482vke.37.1586381360168;
        Wed, 08 Apr 2020 14:29:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586381360; cv=none;
        d=google.com; s=arc-20160816;
        b=vZxbYuedn8lkjyLhPRBKd7SNA7HQScCqcJ/15V8gKSREyKC02c/Uf5FnbyS4NQdC3Z
         HpJf5yJNLZKwSMn81yfJSeyUPKbpXrGQjb0EJe8bA5AWACu/k13ekC+ZmBvOR0+tzXqK
         eLF7HEPtzrFzFPCKLz99bN/YNmQDu58Cm2Tx70OOvWX7EfJdaa7KtIFbKHAZM1UdjxxL
         v2v/3Tteq5FnnjqUjdZcGOc7aOJNI0To6S1gprFNk225dA4tSraC0NhUwPWoPAjBZZ0z
         o1cokXWxxZmKKDq3Ys5DEP+Q/OSztb6bigtDxiaMEKFfVz0X3dtVUSUVWWNOjfkz0QGX
         UCdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=SVDtsGi6neGFRwikvRHYLrFbo8bPwU6BhE0B4MocRjo=;
        b=mPwIy/TecKmR7xdQjwbhn7xCGB6zXRyr5Ws9a1KDm7Jjp/O81pPk6ro1PaI2WtbgcK
         MAifM49A+VihaGgz9VLTMEgF3DC+BfRS8ZhrDJwX/16q6ngT3/JqEmkb3as3ayC8jREN
         LojeY5HQ0JdOGo5ZcGPHsUsr7mAxDF5tUr+eKJFkevw6aPuAGwb05tzYuEZB0D4UuQUO
         9TTJHr7OvqnoGEa6EeL9f3dOTPxNCZcx5EmgYHm7cstbk/fGZy2F/h2bJg8J9ZrZDEOQ
         DxBXXOCAQUvN6Z9d6UQXcYtqlFrTFOokSwb/bbfxnSXfdqwmxIyjSGNmNo+CbSht6bWl
         sjVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=BWwwyhWd;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qv1-xf41.google.com (mail-qv1-xf41.google.com. [2607:f8b0:4864:20::f41])
        by gmr-mx.google.com with ESMTPS id m198si348759vka.3.2020.04.08.14.29.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Apr 2020 14:29:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f41 as permitted sender) client-ip=2607:f8b0:4864:20::f41;
Received: by mail-qv1-xf41.google.com with SMTP id g4so4480745qvo.12
        for <kasan-dev@googlegroups.com>; Wed, 08 Apr 2020 14:29:20 -0700 (PDT)
X-Received: by 2002:a05:6214:b21:: with SMTP id w1mr9649854qvj.69.1586381359791;
        Wed, 08 Apr 2020 14:29:19 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id i13sm12975162qtj.37.2020.04.08.14.29.18
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Apr 2020 14:29:18 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: Re: KCSAN + KVM = host reset
From: Qian Cai <cai@lca.pw>
In-Reply-To: <fb39d3d2-063e-b828-af1c-01f91d9be31c@redhat.com>
Date: Wed, 8 Apr 2020 17:29:18 -0400
Cc: Elver Marco <elver@google.com>,
 "paul E. McKenney" <paulmck@kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>,
 kvm@vger.kernel.org
Content-Transfer-Encoding: quoted-printable
Message-Id: <017E692B-4791-46AD-B9ED-25B887ECB56B@lca.pw>
References: <E180B225-BF1E-4153-B399-1DBF8C577A82@lca.pw>
 <fb39d3d2-063e-b828-af1c-01f91d9be31c@redhat.com>
To: Paolo Bonzini <pbonzini@redhat.com>
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=BWwwyhWd;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f41 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Apr 8, 2020, at 5:25 PM, Paolo Bonzini <pbonzini@redhat.com> wrote:
>=20
> On 08/04/20 22:59, Qian Cai wrote:
>> Running a simple thing on this AMD host would trigger a reset right away=
.
>> Unselect KCSAN kconfig makes everything work fine (the host would also
>> reset If only "echo off > /sys/kernel/debug/kcsan=E2=80=9D before runnin=
g qemu-kvm).
>=20
> Is this a regression or something you've just started to play with?  (If
> anything, the assembly language conversion of the AMD world switch that
> is in linux-next could have reduced the likelihood of such a failure,
> not increased it).

I don=E2=80=99t remember I had tried this combination before, so don=E2=80=
=99t know if it is a
regression or not.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/017E692B-4791-46AD-B9ED-25B887ECB56B%40lca.pw.
