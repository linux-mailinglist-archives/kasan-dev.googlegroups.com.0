Return-Path: <kasan-dev+bncBCT6XLET5MNRBHGP4SZQMGQET3E25QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 44672914416
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2024 10:00:31 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2c7ef1fcf68sf4348181a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2024 01:00:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719216029; cv=pass;
        d=google.com; s=arc-20160816;
        b=MpSNHk06j7UWETiZwalpneWcbknR3qyY/ys9c7ksCPjlmBxywDNZvsgaHphfgbaQMF
         RraScda34Bm2Xm4TXnVrPcNcokxjRhk7Wd6EKDszJ0WduybFSVW7vahX31q7UJojYABh
         EbtLj/lLtizW0K1nF4SjM17Hpw079gHdwVvCYqoQcaTI38gXJUqfffPn74IMpcbX7Vl9
         txUzKZA9zNdHddSI6V0JXlXiCFDmQ4AcbBOpoOcH8a87IFT8mliuZKx5QfmG9oplhks9
         b/ZImPxG0KZXn70t9x4AtCYV6Ct3PE1HoV62WMr6gQWxQAmF3OzL0j52MdppzAzLQ+UQ
         PVEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id:cc:date
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=9u6wSwqvkkuwJ916CgJc0TN2Te2daPLPIUtFjUE/+50=;
        fh=Rn6YGCi7CMorgrGlHedM6CCkQHQJAmAT2fFjsPxCI+4=;
        b=rcLdOSVp3q1ZolTpkb0FMKC7zeV/Snv5tg3BtNz72+U6QlwBKo2hfY8AIn4E7cNCEH
         Av/tMhDoplRMubkMYv/F+lWCb+txRn4vFsxLofxphrbPrT+5GbiT/a7ONfPgEJPlpIOL
         j4KI32B8tXjZNi6iP85ikJ5xaIWC1qcnSM/FF3tnbL5xqiOUIuA+2LDAkjVlfqj4gw3A
         JWGjueeLVN3Y9QbW9ZrBqT8/0VFbzvaCBpqaNgjXYMyb/KHZoWwVK08BtoIw1kmLWxMi
         G2RaiOW+9wJgKTLd7fV6ntVRdoHLaQKYpzneE4+lpRLmI/1gPGnXL8yp/6bdKS8CNXjT
         RO0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@toblux-com.20230601.gappssmtp.com header.s=20230601 header.b=qNBK+QR8;
       spf=neutral (google.com: 2607:f8b0:4864:20::102c is neither permitted nor denied by best guess record for domain of thorsten.blum@toblux.com) smtp.mailfrom=thorsten.blum@toblux.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719216029; x=1719820829; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:references:message-id:cc:date:in-reply-to:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9u6wSwqvkkuwJ916CgJc0TN2Te2daPLPIUtFjUE/+50=;
        b=g1CyB5cWyTnSb5jjGFH1vQ6Skw+DRsHmW0DQExSotbRqEd2XL+FYf9BwpLrpgzOFkZ
         r24CD/OPqeyI7OpcYbvfgT4cQ32tMk/J6aMRoK9aUGclF9NMGOnDl9bTzPjevu1Tfdvi
         h6BtqtWJXFF0lPy24m65GIXMBwp9DsfBWJklSWpB32xLKJTui4/HfKuQcbhY9jcUcn3s
         6zBc8/dKJKh8/yZDFkbSS9mrRx9OLrbdjguqs7Ga8BUlqZnoqPT2lSi9X69S6RvSrFjy
         /H/PxxGH6bZ9Iu5x65fJg0JHa7vjUzYd1BgkaeguPXTAn7npJh/vpHHiqv+64S4mOUyE
         VZWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719216029; x=1719820829;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:references
         :message-id:cc:date:in-reply-to:from:subject:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9u6wSwqvkkuwJ916CgJc0TN2Te2daPLPIUtFjUE/+50=;
        b=Qo95XkDFpdG1UcQroMu5L4K6NaI5e6lUDZ+WYXKLWHhQyfa2aGIGzxMdSM+nwEZ0q3
         DCnyOJzN892PYtYbPZDJtyHHdOADksMfZfzaxnExhtHMCGj/mjtRpgEdC1cM/h+wJf98
         tjDu1nue87pKn7WchdhyVtLj3+df+8A5AQp/gwTZbob9FnKrV+udB/KgSQ8hwZk+oGvi
         0IWROtVZMBb0qzlQp6P3wLEJawpX6+qZNXIVSqdlnRvGboVjZUUFmdEpxh9ggddgOvKL
         HEH6mrH03WJv2/2D+53roWxH93E1nVOA3L1jwDwjoCl1IIOsmfy3Hv5l/FHGAvmCPF9E
         fuCg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXU6Yyzixj/wU26JIkbjpIo/XJzYr0GASrqFlG1qPO5FFC/jvuBX/RXjuS56STR7o7XfIwiOJSkytgujxAe27bwLw3wutYY+A==
X-Gm-Message-State: AOJu0YxgwLquo7QLf1z6YcfoP6Hly5eNIyPeL1Du9QQm6BG+hlwCgpYF
	tLOj9vvimGg/YVOf/gdwMkBbHOggErinyPb8CH/FDrEGWanKpENd
X-Google-Smtp-Source: AGHT+IEh4wE2kwLGBovrAYbVsGLOii2fYcwlNzA9pfIVtb51FbEAStUvvLALnNamMrtZlvfTtkVWGA==
X-Received: by 2002:a17:90b:1d03:b0:2c4:de4d:f9b0 with SMTP id 98e67ed59e1d1-2c850573ea7mr2943435a91.33.1719216028916;
        Mon, 24 Jun 2024 01:00:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c683:b0:2c3:dc3:f285 with SMTP id
 98e67ed59e1d1-2c7dfbddfd8ls2287222a91.0.-pod-prod-01-us; Mon, 24 Jun 2024
 01:00:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXcG2/r9IOIyANb8uCGwU0N8grSYxW3BKOXoRiUUH/4uSCIf1gjd4ZvaV5612ReXRNRV7Dl6PIiLvKIA6nJKFLNH9KKkl+ilRHocQ==
X-Received: by 2002:a05:6a20:aaa0:b0:1bc:e160:d2c2 with SMTP id adf61e73a8af0-1bcee6edfa0mr3547946637.21.1719216027754;
        Mon, 24 Jun 2024 01:00:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719216027; cv=none;
        d=google.com; s=arc-20160816;
        b=LDq7zbr7bUdoqosn9HugTdAsRsIIOkkqPje89JGA6bZ0b1Vw5g40pa8e6/SgItj/vF
         P8iHLjgrmVIUMjtbYmPtZOcoZpgNWc7nGVlVsWcjMvLba3VN3Vv5zGZVz0uVXWvuz2Ob
         we8FaJu+abEWZfax1fyrzy64+vCT5MUBhz/d7FwNlwbl6v/t2GK7bEKK2/m+bkBYxGJ7
         rFd2erdkB797seTcCZg1UItwz3gI79cutjcqzdme68E+EjgmB0Xp9mZQqmwdCDirqBVp
         UJKaOIRfIZi1XKuk1lEngPCe3P91sXbVu+xflW2+957WKEiUxxhu4zoD/qJ/7yE/EJ0x
         ym7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=Aj79LYCAxF+p3+o6X9hA9GUorzi9x84bMVNK8ifZhGA=;
        fh=jD8eaWUbJ2AyrdwRjr77IN2YoUEuTKRuPlUoBlv/sj8=;
        b=i19KUmTl2P2hECQHO9MtC3gr1XySCRU+xmrCxqIa9JMjdyiPOH0IyIukPhmcmLFH0r
         bj26Tyv4ih2PzCpL8aYGp1ozImtZZuxbgxpa5JUB0QPwowmm9+LaN3hh9kzr//lmZlKA
         Fe90L3RFuImbkZEs53VXUv+nrNqq/JRct5CIPhrPnBdO7RtQG4vPqqS3uwp/nEEZ2NYu
         9C1GPj5wE7OR3GrOqqbOPF03Ta/VDewipvThNvR4atIrNnRcQpdTYDBmbA7gjwd2OGU3
         MqgdMc6nlSryNVUSMJRr2JCQ/eJ0nZwjmjCrdleWYuofr4kN8RcNlp5jJ5Gx/NnBhfL6
         5Ruw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@toblux-com.20230601.gappssmtp.com header.s=20230601 header.b=qNBK+QR8;
       spf=neutral (google.com: 2607:f8b0:4864:20::102c is neither permitted nor denied by best guess record for domain of thorsten.blum@toblux.com) smtp.mailfrom=thorsten.blum@toblux.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-717e882aa76si213996a12.5.2024.06.24.01.00.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jun 2024 01:00:27 -0700 (PDT)
Received-SPF: neutral (google.com: 2607:f8b0:4864:20::102c is neither permitted nor denied by best guess record for domain of thorsten.blum@toblux.com) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id 98e67ed59e1d1-2c7b3c513f9so3138482a91.3
        for <kasan-dev@googlegroups.com>; Mon, 24 Jun 2024 01:00:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUru7f+1WfLz/VnP6HDaqmp91q/0w0rH6HYgFbIhagYNvNh/XjB5NSrwqMn+pa4C4hmtG3NjkdbnwHT9tHTQ6M9Eo5NHwunNej4nA==
X-Received: by 2002:a17:90a:3fc6:b0:2c7:da20:524b with SMTP id 98e67ed59e1d1-2c8504c7dbamr3257115a91.10.1719216027213;
        Mon, 24 Jun 2024 01:00:27 -0700 (PDT)
Received: from smtpclient.apple ([2604:3d08:8e80:cf0:98fc:e883:d2e0:acbf])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2c7e55dcdf4sm8077639a91.34.2024.06.24.01.00.26
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jun 2024 01:00:26 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 16.0 \(3774.600.62\))
Subject: Re: [PATCH] kcsan: Use min() to fix Coccinelle warning
From: Thorsten Blum <thorsten.blum@toblux.com>
In-Reply-To: <CANpmjNMHPt7UvcZBDf-rbxP=Jm4+Ews+oYeT4b2D_nxWoN9a+g@mail.gmail.com>
Date: Mon, 24 Jun 2024 01:00:15 -0700
Cc: dvyukov@google.com,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
Message-Id: <A820FF35-B5A3-410A-BAF3-0446938CD951@toblux.com>
References: <20240623220606.134718-2-thorsten.blum@toblux.com>
 <CANpmjNMHPt7UvcZBDf-rbxP=Jm4+Ews+oYeT4b2D_nxWoN9a+g@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Mailer: Apple Mail (2.3774.600.62)
X-Original-Sender: thorsten.blum@toblux.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@toblux-com.20230601.gappssmtp.com header.s=20230601
 header.b=qNBK+QR8;       spf=neutral (google.com: 2607:f8b0:4864:20::102c is
 neither permitted nor denied by best guess record for domain of
 thorsten.blum@toblux.com) smtp.mailfrom=thorsten.blum@toblux.com
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

On 24. Jun 2024, at 00:02, Marco Elver <elver@google.com> wrote:
> On Mon, 24 Jun 2024 at 00:08, Thorsten Blum <thorsten.blum@toblux.com> wrote:
>> 
>> Fixes the following Coccinelle/coccicheck warning reported by
>> minmax.cocci:
>> 
>>        WARNING opportunity for min()
>> 
>> Use size_t instead of int for the result of min().
>> 
>> Signed-off-by: Thorsten Blum <thorsten.blum@toblux.com>
> 
> Reviewed-by: Marco Elver <elver@google.com>
> 
> Thanks for polishing (but see below). Please compile-test with
> CONFIG_KCSAN=y if you haven't.

Yes, I compile-tested it with CONFIG_KCSAN=y, but forgot to mention it.

> While we're here polishing things this could be:
> 
> const size_t read_len = min(count, sizeof(kbuf) - 1);
> 
> ( +const, remove redundant () )

Should I submit a v2 or are you adding this already?

Thanks,
Thorsten

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/A820FF35-B5A3-410A-BAF3-0446938CD951%40toblux.com.
