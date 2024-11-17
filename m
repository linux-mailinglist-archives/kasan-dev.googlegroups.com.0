Return-Path: <kasan-dev+bncBDCPPK4N2UPBBKVR4W4QMGQECYA2AMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id A4C5E9D01E6
	for <lists+kasan-dev@lfdr.de>; Sun, 17 Nov 2024 03:45:01 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-539fbf73a2fsf386587e87.2
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Nov 2024 18:45:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731811501; cv=pass;
        d=google.com; s=arc-20240605;
        b=JDg4W0QEoOvlBn/zLSQoZUhKFH/xI9umzyP7jYvqAQF+6iTdvmQzK/gipyLx/pN9MX
         fXJnDesNdLn+fVJJDzCASLhEwaH/kidm9yu/VFuFkbafo/z9/B4v5+3TsrUXmwjSvVuQ
         zF+P2uVP4DSv8L415NvmUJpZeXqBWgMs833hKm0xeX9GnAFG8d3sP30SSStEQF4hCrT4
         RVKHvchSwXIHYE5/xfg6U6y4jKiMda7JcxkPkyxvcx2gC3w0Uayu3Oy6ZfBD6lgsJrJT
         nDbYEAGNsH/YaGDTv3qbk1/CaMyLFb78lOwpaX5a39toDlM9B389pz8vKfVdgfYWf4qu
         u9Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=jRLn77YzuEu2sUGC/sHyttkByOUoaRpccIzUYlDLf/A=;
        fh=QTcbiFzzcI6JHxWAPUI/A2rSXSKXxYw4A9m/MzKf0Tc=;
        b=kCUf4NmUII7s9Uwg/cis8Xx/0G0FurtUjgxWYww1Uvju7xiWbzDNMrfFQEqui6Vehc
         z3GVyJNiJRXem0GR/mdx1nATLr6g+1EbKhxv95Y3nfyfjgNd8B0xnK+QVS4LEZF9+Q4x
         dTNqrq4ED9tq6I3iAXCoKYwjhTZM4wgknGiosKbSlH0SLGTnVyoWo6y7IHNC0Ujji2dk
         zBm+ZKS5dJREsldHH9qORuTDX9Rgp8QOObXRV4MM1AOjLtopkkaFGTSIhCWD4JVCkCH3
         RYHgR87P8MT67+jSXi7R7JPvijI+iHbksp0YrwpnKlLXW1EddKiyAKTbyGHFE0TlR2pW
         ExWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=O8kNR1HO;
       spf=pass (google.com: domain of enzaapersson@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=enzaapersson@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731811501; x=1732416301; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=jRLn77YzuEu2sUGC/sHyttkByOUoaRpccIzUYlDLf/A=;
        b=YZJ5zccypt439RwhH7G/y+rVxEC9hyNHkd1wG3oPJuOv+jqMNUjzK8o7OvLCT71Kbs
         4Fc3Bk9gAf+phpegTC6tfqWOr/N1N7oEC6XNaphjuIl+JUDLVimN5cZFyPX6eVExjuL5
         oLWfqRZHPGHv6lAlzTn2LBKLI+HZmr47inNySwmjkXsCZtXKpiJVVhqxHZIZh1xW9ujY
         OSw+u+jUMVvGCAedC76IQjhXgc9Pe2vH045klJb2v5F6bjm5FqSDJ7T2fsJS1lhoo0vR
         vqVUpDvqFLzMip4ZKROLzeLJLT6e/jRWDuUfO9SmeJq2WjMjdrUGUAukFl6cYTuzuM3W
         jiag==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1731811501; x=1732416301; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=jRLn77YzuEu2sUGC/sHyttkByOUoaRpccIzUYlDLf/A=;
        b=l9idoonVWwBJ8z/m/bWKrxj+U9YIesBJmeiN7GeN/UD/iAopZx53dOgOfJyd5FAQSu
         MZTZm/woeZfV7qSTm6AcB50hurPqaDGiw0YbDdivPSTj1Ycu8vHdeNSRiyZCN0fRpEdU
         21lUUNHJ/sxraeboC3foB/AI+6ah0q3SqUieg06cE+lg2wAs7uViLF0zUFEaM0CYTdo3
         xLoJ8ENvHSc1LW0ofY5x+4qyoHcdWtlHo5PZLveAqf35paENe+mkdoDy0IARbQjqx3ES
         q53uuv6DmSq2EiRQq7ICtcyroFsr0Rcov2F5gC6haLvHH7wR6flhfB52Y902JE/2rH9+
         jVMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731811501; x=1732416301;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=jRLn77YzuEu2sUGC/sHyttkByOUoaRpccIzUYlDLf/A=;
        b=gwq/rWSsVpNSaMrlrSRRBrWrbVOmmE5SGSjkhNGykBy8n4LGw/bxHnD4Cs6P3S1L/s
         OKZfAfVcN76hJEdjbZWMdFeB4ufwT4KNuOCUmSmOF9t36nzzqSc4DXdMZjF/MmqcwhMs
         HoSQSh85ljjHzNuE+WR/m4O0Q34p6MMDEq5HTLA3TbKZ7or84tK3FS4UC9+kW5ldTzMW
         bWKQXjKu7SMopLl2qtfPV1xY03mOd0y2agoqHc7oJ1gtD04U+Kyhgdxc4KksXsXoD4qr
         LjO5i3QYUbhORtVY0WwuAwh4jrklCDr2sFIgk/PB+dWwFtnf23qPrG90TPTRRJGgg5mP
         13QA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUvMi8TrmN66MDJ6xVX0ntiEny8uog0xNKcdCtbvWbDHVFtLxfkmwvoaqk6FMkf1pCCv1PS5A==@lfdr.de
X-Gm-Message-State: AOJu0YzRLOV3y4aLZbbUVygzrjbB2UwkMaNoQeCxzR7PtFKuHKHrXQaU
	6tF2iyAcEapVSy4p7+YXs076ODTZMvms0dvGeaxi0oROIoGDtlUK
X-Google-Smtp-Source: AGHT+IHASnXGuukpjDmn6TGRJ4yz66kILdOY4+y6AQAwfUC9hZbYxub0xdqxg99HtRVvC+ap1l1RfQ==
X-Received: by 2002:a05:6512:28a:b0:53d:ac13:795 with SMTP id 2adb3069b0e04-53dac130809mr2435998e87.0.1731811499598;
        Sat, 16 Nov 2024 18:44:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d27:b0:53c:75e8:a5cf with SMTP id
 2adb3069b0e04-53daf5ef2d0ls68622e87.2.-pod-prod-04-eu; Sat, 16 Nov 2024
 18:44:55 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWgUlir6KyHj4e5p1jxmEk1do5sj2AcX+8WAoKzZNfB/fApNUqMzXu2Q3QwyzWQZQZIE22KmkqkKyc=@googlegroups.com
X-Received: by 2002:a05:6512:2245:b0:52c:e3bd:c70b with SMTP id 2adb3069b0e04-53dab289eccmr2987676e87.1.1731811495621;
        Sat, 16 Nov 2024 18:44:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731811495; cv=none;
        d=google.com; s=arc-20240605;
        b=Z73w9hm0b7uilHcW4EHaRfzc66nMy4W9Va/63saWoGH7MmeGu2kain4qr44d9WtaOc
         /x9ZbjuQrgaHkdVJQc4jsksmiAfDfx6ah/B7HGNnpnw+fKWnd1t4HTK/ubk3ePtpKIqE
         EMjKz4g1AXE8bk+lyRJZLKZfAZf1sEAUh4+CDmWnf9XR2eNrElD6XfNCq/4FuM4X6uCm
         cBqRjns74kwQN/ECqF1mhFA4LwX+t+n2yKavnIWFUaxpB74+9Eun8pGgJKC0phtjcg1X
         lkN3QlCy3ZUcD3Oy4yrHdZel1/HEvPxNmpEeLKbmoQOBVvwCtAwm/KaFAMJzc8CNLC1n
         a0lQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=BRcyRBkj4RcIpIbEZrJxQfFo3J5M0sNpXx0tUVzocco=;
        fh=yN2sOqW7kzO5lfpSMiZYN+cC5qQgd/Qd4DEtTklxUdY=;
        b=awyqU1Nlo14Mp24NA+iZPOxq+QK+V0yDz35Xt4HFGVhzIjzfc1NCJCdTBMq+m0beZl
         TG6reQWYXR+EezK/PXNn+DXO1M08oHWROTRurb8iV8OZd220xM64fWC7GyCmiWTiyJ1j
         MIQVEJdvsWA9m+Cu2cTYLjpuUeZgyOWQjnZQxAZNPcW9U4ZYzfeBrbGP8wywAMblpKmH
         p7xZMSQlIU8hqVTnPo16gz/C2g8uMNHodRu42sGGpBf+CASLwKyYFrGEX65pDXT24ksG
         oyg8spzjzK793qBohQEV1+L6GHNs2IDlhdKoUd65tz1LIzB+RkKEwbAWyeAKLgyeGGUx
         ZJ4A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=O8kNR1HO;
       spf=pass (google.com: domain of enzaapersson@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=enzaapersson@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53da65014e4si233380e87.6.2024.11.16.18.44.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 16 Nov 2024 18:44:55 -0800 (PST)
Received-SPF: pass (google.com: domain of enzaapersson@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id 38308e7fff4ca-2fb587d0436so6246321fa.2
        for <kasan-dev@googlegroups.com>; Sat, 16 Nov 2024 18:44:55 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUEEGyASRyDIhHk7acQ4XJDANc21jux92TqQryP5LzM61tn1BrFU0TvzMyJ4gL/devYsUdqGOJlxAM=@googlegroups.com
X-Received: by 2002:a2e:9fc9:0:b0:2ff:59be:7c77 with SMTP id
 38308e7fff4ca-2ff60662397mr34116701fa.3.1731811494970; Sat, 16 Nov 2024
 18:44:54 -0800 (PST)
MIME-Version: 1.0
From: Enzaa Persson <enzaapersson@gmail.com>
Date: Sun, 17 Nov 2024 02:36:51 -0800
Message-ID: <CAFsQbgAxs5uj2gAWQuwjwC_aKWeBkV5fHV+MESfqwpZ0aiwU_A@mail.gmail.com>
Subject: Hi
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000f9d23b062712c869"
X-Original-Sender: enzaapersson@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=O8kNR1HO;       spf=pass
 (google.com: domain of enzaapersson@gmail.com designates 2a00:1450:4864:20::232
 as permitted sender) smtp.mailfrom=enzaapersson@gmail.com;       dmarc=pass
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

--000000000000f9d23b062712c869
Content-Type: text/plain; charset="UTF-8"



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAFsQbgAxs5uj2gAWQuwjwC_aKWeBkV5fHV%2BMESfqwpZ0aiwU_A%40mail.gmail.com.

--000000000000f9d23b062712c869
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CAFsQbgAxs5uj2gAWQuwjwC_aKWeBkV5fHV%2BMESfqwpZ0aiwU_A%40mail.gmai=
l.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/m=
sgid/kasan-dev/CAFsQbgAxs5uj2gAWQuwjwC_aKWeBkV5fHV%2BMESfqwpZ0aiwU_A%40mail=
.gmail.com</a>.<br />

--000000000000f9d23b062712c869--
