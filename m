Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBL65YDYQKGQEQ27VPNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 93BF914B47B
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 13:53:04 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id o5sf3249033oif.9
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 04:53:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580215983; cv=pass;
        d=google.com; s=arc-20160816;
        b=SK5AUaYsKr5NsiyWbxbP5W9Is4SUB1KjUtHfN52TFvwE+nrZiCOdGPU8ffKkAiDnr4
         OTcI3O4qMNlw6pW+WSbySb8ky8mac6KnDbzr7W8SwOJR/l9cgV2D4Dhq98vx8O8VQH2y
         VCX8RtQrg52P/mNzuxM6Rr2utFQBhZT8UUTg0MV/DQRU/Vzessqwq55rTKVSnsrPZDx8
         rch0dUsTWrGzcS/dHHa3L6V1beolw9wUimqSQ4rz5G1VPQx+3k+p4N+5ZIm+RsTB9lQ8
         ZRTSJW4Ai1FuyjvI9r0QIQdk31x5+Ldxc/PCVlNyW0IgSHu6avBjTWOD5P4pkGLLtRlO
         tO4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=qddjdtIpI8eSetS5W9IJCjW6d7q0Ju7jC4LI+68NeNU=;
        b=YCuoAKewNCY3fPS7jHwpnKinG2e/IiJn7mVmJHhUMrMdlv56sAyP94CZgmLZK0C7Cr
         7iBd568A6sMgVwmmU/MeKuJ/qzKf86q/p254KpevbDFkPGwlZvAK6gZwV2yQZ0yOFUDD
         JVA648CwxbbB0rijzr/pczuREcuCo5+Eaz7rv6PRCjuXcS4NjJEumevkDY2hVoEdS4Pk
         D2j2UNbooEhlhLuYCgL4CmQqMxVUO4zMtbF3vISABmSkO3RZDudhwFCxkgLjMmDAKUdy
         1xaV5AV2sfyusS01y6awZau/YFeqzOGB5lYk2Vp2L4c1XqHYf2NxR/PDNnWb3PvxaFqs
         m7bQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=Z2sdRUs8;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qddjdtIpI8eSetS5W9IJCjW6d7q0Ju7jC4LI+68NeNU=;
        b=fXgbfvw2sUFd3h8Cew4EutklgKOap+f9Bt/0xq5SoewfSd5Ep38/Kb8iFmQRbWF1Q/
         9e39XJaL4HlY+xv1xQjhnrgiEr0tBVdpKwDmNaRleR7Wlow9BYN6czCWGV9vti185a28
         e7HnK4YwdJE2kbeEjrvLFeQISsiXbD1pIypApSvkroNvqio2OoQZOaj3sBqk4ykHJVKn
         oSCv5cDMMXZq4ZyCu00tZT0+bZ7SpoJYIPdO2yAJ/dJAtdvl+UHFA45Vcw1li1oioEDA
         JUAbE1A0KX7TPMqU4VK3qbU7lS+SczH1jH/EpM2hZqzHcM7BtAZ+hnMd9Gc1vsSatA1H
         B2EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qddjdtIpI8eSetS5W9IJCjW6d7q0Ju7jC4LI+68NeNU=;
        b=Ln9e6oUg8Y81VLq5EZ7pxOiYCT6TGVa8NtEnqhXYq2vRpZmCcnDqcYSzKdvvFU8H+G
         NJRFTspp9hKcZLpKIiiMBKqkIo6PeH+dHkdyc6DAJoRR5Az2NYEEzqbuOguJlQSH84Sj
         f0yrD26bSCC+SWaOQsc0NQRVJns0cygoSewZ7s/FDuHmRKsm5PQIh2FFfR9NIPzx3rDE
         KkdwGksbqhLs/uyO8+XlpwXAS5BEB9uhanKnkY1B2RYCneuqvmyyA7UH7V5ThFHj5zXn
         Nu4U3tuHl7Vx8+LcDW0AwF9cbGJb0V7Yj8b/Vp8h/ovk7IvaSBj2hCIswnNYNMGyPoeJ
         W/LA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUnlx8JI/y/Wi0QRbl0sZQsR2/5n8ROIlQDzM2a3wSnvWKGyDs2
	pmJmgsscKeb0/KJ5HUmthKc=
X-Google-Smtp-Source: APXvYqx9V25sCD7GR6dgRaQJn6RO2TE82aGsaz30XZ+nbO1F+4ZQMC6nwWsEiOKHNtfBev3KmtZcTA==
X-Received: by 2002:a05:6808:9ba:: with SMTP id e26mr2715267oig.81.1580215983206;
        Tue, 28 Jan 2020 04:53:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:649:: with SMTP id z9ls2160182oih.3.gmail; Tue, 28
 Jan 2020 04:53:02 -0800 (PST)
X-Received: by 2002:aca:4fc2:: with SMTP id d185mr2704166oib.33.1580215982848;
        Tue, 28 Jan 2020 04:53:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580215982; cv=none;
        d=google.com; s=arc-20160816;
        b=baqehBVdALBlLLD/XC1HWMVfpFpqnwtL5Zae5O0dp/QVdtJCAXtKXgkkscu2yn++hQ
         xsrpLZKfvb8L2BAHV3v5w/CaGULcjGliEGqX22JPHA5N+qfl/TdxyxjcKzrkZ5I/s4wB
         xDcW79bbj9GVnHeoQtlcJ29Am2DyntL5ISj1ueuKpAnbi9K4V6t8WIRuso+rlRvJSXqH
         TLLdx+lgh+6HID2wDG8nctl4sEyQNEWKz6DyD1D2OP/8mRpruxJfMWeQkuSXCN0BIrC4
         ahkDW0Yd2KGkURsdpfZ0yX5zCsELmMwQAlaAWWsm5ibWtFK4zHMy+m9OImTVqJpyhXiP
         0J8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=9DB/J78WdEiWma3kq2rh8LijmEsmMv+++6cwRIocUY4=;
        b=vVvTh8mxMNQEuk61B3FX3xFUpCZi2zcrFEyuQL+lYrjYIBuc3uFWM3n+1alYB5gUZO
         ANAnG5UvhgB4FcQoVrnSTxLaIuM8qPKlSnokthxKprM2lxVAKUHE6yN+/PWGJfzH7MpC
         Ew+QZ8qZY/akTLXvLpN2YBfhM2UidyE1VH/v7srjzOEnIf7YSq7HwqaGWEfOb848DQRK
         MAFt+IJU6qtlyCY1HRj+zyHp4mI22SyO4KGkXh2BWwENtRb/MVcGw6yxFQ2dMksuHuw4
         KWy2lwDwZLG6SwAur3bzxZxiCc6qEUy9Ldgnw0JujywUeRPt3+IzcyzU7sXIOWefzT/Y
         VZgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=Z2sdRUs8;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id r12si591123ota.4.2020.01.28.04.53.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jan 2020 04:53:02 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id s7so492689qvn.8
        for <kasan-dev@googlegroups.com>; Tue, 28 Jan 2020 04:53:02 -0800 (PST)
X-Received: by 2002:a05:6214:965:: with SMTP id do5mr21816222qvb.202.1580215982182;
        Tue, 28 Jan 2020 04:53:02 -0800 (PST)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id n55sm12637616qta.91.2020.01.28.04.53.01
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jan 2020 04:53:01 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH] locking/osq_lock: fix a data race in osq_wait_next
Date: Tue, 28 Jan 2020 07:53:00 -0500
Message-Id: <C50F23AD-7CCA-423B-9C13-E06596CB4399@lca.pw>
References: <CANpmjNNo6yW-y-Af7JgvWi3t==+=02hE4-pFU4OiH8yvbT3Byg@mail.gmail.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Will Deacon <will@kernel.org>,
 Ingo Molnar <mingo@redhat.com>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 "paul E. McKenney" <paulmck@kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNNo6yW-y-Af7JgvWi3t==+=02hE4-pFU4OiH8yvbT3Byg@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Mailer: iPhone Mail (17C54)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=Z2sdRUs8;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f42 as
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



> On Jan 28, 2020, at 6:46 AM, Marco Elver <elver@google.com> wrote:
>=20
> Qian: firstly I suggest you try
> CONFIG_KCSAN_REPORT_ONCE_IN_MS=3D1000000000 as mentioned before so your
> system doesn't get spammed, considering you do not use the default
> config but want to use all debugging tools at once which seems to
> trigger certain data races more than usual.

Yes, I had that. There are still many reports that I plan to look at them o=
ne by one. It takes so much time that cause systemd storage lookup timeouts=
 and I needed to manually get out of the emergency shell.

>=20
> Secondly, what are your expectations? If you expect the situation to
> be perfect tomorrow, you'll be disappointed. This is inherent, given
> the problem we face (safe concurrency). Consider the various parts to
> this story: concurrent kernel code, the LKMM, people's preferences and
> opinions, and KCSAN (which is late to the party). All of them are
> still evolving, hopefully together. At least that's my expectation.

I=E2=80=99ll try to reduce splats as many as possible by any data_race(), d=
isable the whole file or actually fix it. Any resolved splat will hurt the =
ability to find the real data races at some degrees.

>=20
> What to do about osq_lock here? If people agree that no further
> annotations are wanted, and the reasoning above concludes there are no
> bugs, we can blacklist the file. That would, however, miss new data
> races in future.

This is a question to locking maintainers. data_race() macro sounds reasona=
ble to me, but blacklisted the file is still better than leaving it as-is.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/C50F23AD-7CCA-423B-9C13-E06596CB4399%40lca.pw.
