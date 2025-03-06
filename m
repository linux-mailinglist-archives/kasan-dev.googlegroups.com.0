Return-Path: <kasan-dev+bncBDFKTTUNQMNRBKFIVC7AMGQEAG6Y3RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 321BEA558CF
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Mar 2025 22:31:22 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-3912b048ed2sf592903f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Mar 2025 13:31:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741296681; cv=pass;
        d=google.com; s=arc-20240605;
        b=IVYl1XZf81ejYBzhS/4ZY0958PAXpz12DW12AhVv3qNr+DQk8ZXjFTnNukctUmCBnA
         kMBqvCpBAb4cTIc7ke1Ka7nlVnkq8yaWRLcYizlsYikwf8MaF3n05qKdX75TpmdWAV0J
         N3pqzWnJvrZIkYAd1rEyXw+RFkfyH5sNAgAvC/XgyZ4KjYM6IjseE2v4541ia8R3TBrn
         uT6aSfFsFmx2FzwxzMbjtoCN+t9YJFqWqdpiHEOjm1/K+u8H0VlZc5kTnVPQYb8S+IET
         HeOjVaeY9ESr1Kqr7uwSLZKaR8m227QFsu4jEBcbMtQNM26VknyDzhcFIYGkW0/bzWFT
         kxJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=dDzQR1t1Z1XyBYVnYUoCdvQT+V7TLLBam4X5Cnjp1Lc=;
        fh=jzIq35MsoYpk3o/vAI8fkEnTWIAFpWqWoc4wPzUWltQ=;
        b=YjOBLMGEcP4DnReOhpbulnwZ3bVSERtRhwI1S2qTiJ1fNG8y3SHFdUsNcuBo8tvsKn
         yC7Q8PqDgAk7HbGR5odbmsLGi/QnXoPxxT33lZSVOP4q1kTT4TFYLZqJDIxA+p6j8BOU
         RN7cEAoW4YPDxvg7RV6RvJ4nKQfaBrd8O95Rn+o5uNEek5UxaYr08mtlC+Q0HH3BriQS
         s0wqScIfKRyhFgpD2gxtFRSVT2KQVghRRv8DWeQhCGzK2uOc8VDDcSRGRFvwY3pIhTYk
         1MMyXXJN2i0CHwAt29DaPw0O+rN6xzeSF4t7zdmXSrClJTe6mYSxSUQATBkPyZLhV0+z
         2KPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=R9WQWruE;
       spf=pass (google.com: domain of qkrwngud825@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=qkrwngud825@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741296681; x=1741901481; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dDzQR1t1Z1XyBYVnYUoCdvQT+V7TLLBam4X5Cnjp1Lc=;
        b=JcU5euTeE1R29h6NJVyIRRntesFE9di5BpppCCns27G/nwES1kBMe+E8znIZn4bgDO
         kX0JPHf1g0l5soYy4wU8qPk425YwRuUKUc5rJFrQ3p64X36aeoS2blDlpJLK6k7QNRnl
         z9wBoY54r9u55oD8HZ9GYnun61WfFPT2rP3fUT8/D96IgOWlMeGwrwd/96RCw7uDvazW
         FXbzSVQ2v8e4ueWWyn6OQIVwQVpCPjfsRza2InbIN5GJLkJcUYCneNwOqxqVlzNn9Ram
         e4qhJoopqkMCBbz2N9L9DomIUiCIysX0GEkN6TOOI3TgJYrUs9BkEcZpkumebKyd2Y7n
         L+fg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1741296681; x=1741901481; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=dDzQR1t1Z1XyBYVnYUoCdvQT+V7TLLBam4X5Cnjp1Lc=;
        b=IFHUosL/CGUO0bx8Mktuq4/v5l8ZcaOls4z3K3CyrIzvJXKpURL1RZDCBC5T9j0nv7
         nBJ9LH95b4nQidqxg3jZdDrkQEId/KeemfF9phz9I9nnSjpopBwr1jNKW0FzUCu/IC/B
         58h4d1UVToe98Bu2H8wP4SLKJmbsiNiqpLZ12IsH2Xl9AlYIEbXp/qrzuRv/mIgUL57K
         sti/ZypzqBo3Pz1V+jXz1Q3QTOG9mhB8wmI2erMcph4JtcqEwcpITRp6XxdfZjyqa1PA
         Bhzt0HNhASe/6nsd3PH6D7DGncf1cjplc6b8Dpi6rGRksH1V/UuPIMYT5Rda9x0FCm6H
         3qRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741296681; x=1741901481;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dDzQR1t1Z1XyBYVnYUoCdvQT+V7TLLBam4X5Cnjp1Lc=;
        b=UVhZq5EmktY55tQKmckvxCibmQ+oonCQM/ewbRWGUVr7v9H8dFvD2XPOMwKzE+4AI5
         akmoVjNy2We9W9/fz4QmAKxf0zOt/bR3t1c1uriA2Ppv9vOE3reIluheGE9Un6LsEJ2Y
         VKnAzln79iuYLNKTW9boyPQ9EqScQIVSAkaIs2eUsKdmGZj7h79iL32hQg/9eTw58Vyy
         2F1uCtDpj0ZwUI8qB3e3WuOE79dFY3JBcVygaHpVEAyP/fkv6VZXRceHr0IRCi8FF7yc
         KUYRBmZYBW4f8ktaLnYhB3YtBHB9i6kzJ+yL4n4fC0Oh0plhmOAW2NVhH+oTF/YTBSZc
         PVDw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUxGVMs8YfELchQ8vUhUCbjofxAxvHogL0C8T9tzorwMbWBvojjGuhyMs0968ob8GgwdKcGcw==@lfdr.de
X-Gm-Message-State: AOJu0Yx6kkwuyc1xR3bLhqWyE1rNnB26KbrB7t9xRGmKsc/UZpMJzLCk
	T32wqW1vFIAsN0CVYlQqjxSypGK17LMgRiAfccLcF4LV5/OVCHQo
X-Google-Smtp-Source: AGHT+IE1+GcWZ+2PbFBqk2djApK+ByO6UXCpQboGECjsjkPB3yH7m5U3gVEv/cUMcCCXq1vTaI19tA==
X-Received: by 2002:a05:6000:1844:b0:38f:4fa6:bb24 with SMTP id ffacd0b85a97d-39132dbb511mr502215f8f.39.1741296680472;
        Thu, 06 Mar 2025 13:31:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHa2SMIstet0e4gF4Ma/tIXd68CLeeiiCBZvkXFWCdjTA==
Received: by 2002:adf:b64b:0:b0:38f:2234:229c with SMTP id ffacd0b85a97d-3912968cec1ls289350f8f.1.-pod-prod-07-eu;
 Thu, 06 Mar 2025 13:31:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWVC7WU3HLAaCJ01dPOHwJcj/o/Wx5VZkUqNQOYsfDcLeh0ZOtne/uFrhbOisLJBGRAR0EFSuUxe9w=@googlegroups.com
X-Received: by 2002:adf:a29b:0:b0:391:9b2:f49a with SMTP id ffacd0b85a97d-39132dd8706mr262939f8f.55.1741296678208;
        Thu, 06 Mar 2025 13:31:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741296678; cv=none;
        d=google.com; s=arc-20240605;
        b=kUPvrubprAE5KhxSNJMJNEsfOSl9BZNM7HbBtPBM5BACrG2sAnrgPcPOgTju0Ms+Td
         op8Keqf+yMwzU9qq9OPUXXJH/KXAUuVbeuJuYlK8ge9EL+HqiNACJxzlGSCct6LvFlU5
         be7vPulIbP4tghW3Yvlt0L/cXfCGeH6QBe3fufxojKWE6yxY9f9JEiWKNGdkp42dhKET
         1ELcE1mHAY9GYew8ZkvxH07oWDJBKfnzTyKZmgd/Znz6WohrB5Cf1CXWXOdEH8Nu/Vtj
         /NxpY/qo9NxupSr962LlSrAStM/ooywrXdsUoCjr2Mxl0JntFXvTyZnDhcE+vXnqKU2i
         GhUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=kE96yKugWc3KCBJ+a0ZR6udYXEq/a4KC7H3aAoxhvGY=;
        fh=m+KubIO+GS1UVmP/lBLzaXb6Onca7bOaUqMGaFLmblM=;
        b=idaszsSaaefsAWyWQi3l6FmRylx1Y6Lo8xRSpMDea8ULL8T+NNLr9wHidujYczZvhc
         Ozpa/005YWmakERniQPajaR8b7Ff1B7EJTiVh2+ga4gssUkxHdi2cvVHJ5fupsOWat1K
         F98uWjRkX6bK22vEOMAJ5DrllVScT9s+O0WYiIrZRfd3U7qfum5Z/n1wKSoNPhDmYh0i
         Yrn1ND6uB16i5H0ouS3iQ+iKv05sXZBC21vLZHSYx7oH+Z8xv0XZLSvMZ/DhTtov2ohe
         MbBZObrq3Z9f+9JWH04fasD/p3t01UNytXrFRSo8bU+mBvNXrQFYTvoaJQq0xIVoustE
         1d/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=R9WQWruE;
       spf=pass (google.com: domain of qkrwngud825@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=qkrwngud825@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x629.google.com (mail-ej1-x629.google.com. [2a00:1450:4864:20::629])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3912bee0030si67146f8f.0.2025.03.06.13.31.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Mar 2025 13:31:18 -0800 (PST)
Received-SPF: pass (google.com: domain of qkrwngud825@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) client-ip=2a00:1450:4864:20::629;
Received: by mail-ej1-x629.google.com with SMTP id a640c23a62f3a-ac25520a289so10517166b.3
        for <kasan-dev@googlegroups.com>; Thu, 06 Mar 2025 13:31:18 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW8YrArVxhvQ/PGGNWgldUvQFT+AC3GkiB/+0d8jZSaOAf7XVbey3XdhBf7rbJD6GuQ3oNDaZ+tGjw=@googlegroups.com
X-Gm-Gg: ASbGnctiRG14kbNc6UnNLOA4DNYhj4NoWT6VnYn6Ln9o29T242xVH0dx3MqTackt/Vj
	Wc2nQu+Y3oP7vfGBgOu9CQUXKZPS2iOHWuVWWh1bdDJXZLRMbprZze10dw9B1OqkLsS8yJkPKij
	ZIRad7LZyzB/AMfEupnjjwOcFR9Z4=
X-Received: by 2002:a17:906:f59c:b0:abf:63fa:43d4 with SMTP id
 a640c23a62f3a-ac252fa2069mr63782866b.44.1741296677308; Thu, 06 Mar 2025
 13:31:17 -0800 (PST)
MIME-Version: 1.0
From: Juhyung Park <qkrwngud825@gmail.com>
Date: Thu, 6 Mar 2025 13:31:06 -0800
X-Gm-Features: AQ5f1Jpyv8dI-koR2gUo5_nO3n8bs0pB4R1I9QeAhoqdJPGMNwh2ybI-sSD0ctk
Message-ID: <CAD14+f36wTG4jYMgdNdNL13ptzqfKGsAQbTqsQvaYe50vLHTFQ@mail.gmail.com>
Subject: What needs to be done for enabling KMSAN on arm64?
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: multipart/alternative; boundary="000000000000e651bf062fb33992"
X-Original-Sender: qkrwngud825@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=R9WQWruE;       spf=pass
 (google.com: domain of qkrwngud825@gmail.com designates 2a00:1450:4864:20::629
 as permitted sender) smtp.mailfrom=qkrwngud825@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

--000000000000e651bf062fb33992
Content-Type: text/plain; charset="UTF-8"

Hi everyone,

Since Android kernels enable memory zeroing by default [1], any downstream
forks that want to disable memory zeroing for performance reasons need to
manually fix quite a lot of uninitialized memory usage.

Some are especially hard to track down that involve userspace daemon
erroring out or IOMMU faults.

KASAN and -W(maybe-)uninitialized are both limited in catching
uninitialized memory usage. KMSAN seems like the perfect solution for this,
and yet it's not ported to arm64 yet.

This was first asked in 2019 [2], and I thought it'd be worth asking again
in 2025.

Are there any (wip) progress in arm64? Can we ask upstream for KMSAN arm64
enablement?

Thanks,
Juhyung

[1]
https://source.android.com/docs/security/test/memory-safety/zero-initialized-memory
[2] https://github.com/google/kmsan/issues/62

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAD14%2Bf36wTG4jYMgdNdNL13ptzqfKGsAQbTqsQvaYe50vLHTFQ%40mail.gmail.com.

--000000000000e651bf062fb33992
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hi everyone,<div><br></div><div>Since Android kernels enab=
le memory zeroing by default [1], any downstream forks that want to disable=
 memory zeroing for performance reasons need to manually fix quite a lot of=
 uninitialized memory usage.</div><div><br></div><div>Some are especially h=
ard to track down that involve userspace daemon erroring out or IOMMU fault=
s.</div><div><br></div><div>KASAN and -W(maybe-)uninitialized are both limi=
ted in catching uninitialized memory usage. KMSAN seems like the perfect so=
lution for this, and yet it&#39;s not ported to arm64 yet.</div><div><br></=
div><div>This was first asked in 2019 [2], and I thought it&#39;d be worth =
asking again in 2025.</div><div><br></div><div>Are there any (wip) progress=
 in arm64? Can we ask upstream for KMSAN arm64 enablement?</div><div><br></=
div><div>Thanks,</div><div>Juhyung</div><div><br></div><div>[1]=C2=A0<a hre=
f=3D"https://source.android.com/docs/security/test/memory-safety/zero-initi=
alized-memory">https://source.android.com/docs/security/test/memory-safety/=
zero-initialized-memory</a></div><div>[2]=C2=A0<a href=3D"https://github.co=
m/google/kmsan/issues/62">https://github.com/google/kmsan/issues/62</a></di=
v></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CAD14%2Bf36wTG4jYMgdNdNL13ptzqfKGsAQbTqsQvaYe50vLHTFQ%40mail.gmai=
l.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/m=
sgid/kasan-dev/CAD14%2Bf36wTG4jYMgdNdNL13ptzqfKGsAQbTqsQvaYe50vLHTFQ%40mail=
.gmail.com</a>.<br />

--000000000000e651bf062fb33992--
