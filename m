Return-Path: <kasan-dev+bncBDQ27FVWWUFRBWEVVSDAMGQEQ2BMQDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id A226C3AAEF8
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 10:42:01 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id y22-20020ab063960000b02902782db6cf24sf2322837uao.20
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 01:42:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623919320; cv=pass;
        d=google.com; s=arc-20160816;
        b=LCmSzUBKJoUdWo/6EeSXUXI9GsWcxJOiKYScK8tlGissbN4DdIvC52guEtbOS/N/+Q
         P3AGtKED3tBSlAac1+jM8QUikpSN7VWZjWiU8OUBVEJrdsvPrkVweEGrEwVm5dJtpRlE
         Osi5bNv1IY92VenwmUFTkvYKaqBlFk2phHNGW4vALwECP0xHlK1zNYHxG1rbAD5xcurg
         QKWgjaugW+M0i8ngToJmy/oGfD9Iw5lHl0XOr4ohUFdC5KBSRF5XuI+6mgUPbgmC4isv
         Q8d/SVXl40y1bMS5v7MbziFH/M8Y+nlDXa5w1Rqj/tvYhohgoXnRTFVB4Bfwc3sV6Ra2
         hlBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:to:from:sender:dkim-signature;
        bh=+YbUf5L+04jdbYPlImh9LC9/+JMgYz1WRkvpcqxJi50=;
        b=ns7QTPkN8w3GU7KKOiu3n50VCWtMAgD+ABNs+xfXq7ZwP0yhgdnhcmOhz32qjvz5W1
         YoEwI2w8tDniIluiqN+V6IvEv4FDbcnQ20nt1J5GmqA2E0fzwnLt5GxhpE7Apadzc1NV
         PB/BaZFuZfEg5i2nGN3Ik8bNg8plVakDv68ajIxM0azQN5QumXKZ+VgPJmeu/c7zqYYE
         UjuWw9kbNgd29bs8fBaPcc1q3aNCnBN7Fav7gIDGjCPW9cQSYraMyBt9+5B1DDPQgRHG
         FNl4r82LSYT+4oTcPbkWcR1IHIrGNFJbOcuqXr+mMtnVVua9X1I8U0fS61Xqx6T7DA2E
         gLHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=a9SCF0Kr;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+YbUf5L+04jdbYPlImh9LC9/+JMgYz1WRkvpcqxJi50=;
        b=oqfn1yCdDVgaMVTbuFqPtVOWqe0dV7t2MvIqGB1WjQSNe97x2kjKrmMk9mbR5JtOGs
         96TtvHMevQCcxlXWW6DrLOxREhaTlyL6ECuk2t8RTBqj12tA0337Ya0cTllpdtx9yHR7
         5lECBe69iZwGcCyODxZYH1ZeDv2yHvHSfpr4bNCVT4yP+VtqLMoysXVYxXyzI07iUV/Y
         2HDM7Fj7zMj+/ENT6oziYALsNaAggsV+2SKMlNE5reaTVWrGK9DUTK7IWZ+/69ROSAw5
         63pSv8Jd3y3o0JFvq99kksUlg6wjGqSIi2w0KUYr0QV9gjxq1cq5JaxtEE/A3GxCk7ke
         NVPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+YbUf5L+04jdbYPlImh9LC9/+JMgYz1WRkvpcqxJi50=;
        b=nZY7dgj/zQCvRqUo95gCFjh4FqOyAh2mETSdWCo2cci1O9YupwJCUVRb9HItMSrvbO
         zND85xxLk9G1oYAUFKXxR+ONw9Ql9X/uzakEV4QjjbEHTGHlYS4NNAukpfCf5hmOYGHo
         PSngDHjtLgiNMCpiNILl7x1k96LfKOAUly38RfEAKiBjD3yuDhUPjLqE20eLh7dfRLGL
         H91YHDceZKcc1khwCWG0i/C9S9daCh6PQ76vgdIksggXlv6UqjPKLagfI6rgKJGb7q3N
         BNAAjoawKGRVN+s7FPHyKXdfMMLgmGJc7pB3VgSrLIwFX1Pj2wsNd47Xuu4CW7nJi+XQ
         liNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531hEotuiY1GgvD86uba21QQ7ME+Mn5LvsPYOy+QsEv3F7sMxHV7
	nX1o3J0SqHgZ+Tub4EeZvHg=
X-Google-Smtp-Source: ABdhPJzxTyT82wdVJLsMCw+7i5XsAsQKzSHnV2BTC+GTz6HePRz6JJ6hsVYau2EM4i+Chtq7f50nTg==
X-Received: by 2002:a67:f4cb:: with SMTP id s11mr3299635vsn.20.1623919320543;
        Thu, 17 Jun 2021 01:42:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e9d5:: with SMTP id q21ls1269256vso.3.gmail; Thu, 17 Jun
 2021 01:42:00 -0700 (PDT)
X-Received: by 2002:a05:6102:c87:: with SMTP id f7mr3144253vst.16.1623919319991;
        Thu, 17 Jun 2021 01:41:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623919319; cv=none;
        d=google.com; s=arc-20160816;
        b=ez+EeyiadaRK+qqvhVRHFQFSacaFAwp/qnU2N/pjDXMusqmL45rkmW0uR6PrdpvNxv
         qwgrtZxxXU7qLGfhnErq2zHd+QzB5D2gGHi8ZNrpFQdN68EIqJGAE7F99iiMFTEZeTCG
         79Q3Q89tvjxUmKB61BsxnCx/PE7y6gGhL79g1NEt9qlLBKS6JbaQlxI5lYK/wGudxOW6
         aowSjY2mpNkRAWspmBPXy4x8ce7SPQf/1HxplJii7ncZje8/kPXPGPY8oVHXhqdR1R0D
         gIEm+D3zlRwMw0PUASJZpT74d2qpjTdGYH/HNLRIWQPjymatyRduF2nP6eP2Xcy7/8rN
         L2/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:to:from
         :dkim-signature;
        bh=lxJo5PuMBAlIj+4qt4jOhSYA3AeZ4kgUXEmzLhpX6KI=;
        b=Zb2lxIzLgriEI6NwI1eg4ZX7eg0IaiUkZMhlRXLPa27M+NgoRQSfNzXgnvv2sWiSKB
         pTzpL84RNN98cT6h88A+7Oar7iFnPHL3JhQ8V8kXP2XBj3umeopyd8NATV1TJmaiMOi5
         IgCTaUYjlperPe/GGfqYO2zLgza+LdQG/0aUYUxeFWInUCcpysZUm74CfLvVEk9tKjlr
         jz9/KAS+ColWyBhmc9xJpiHbbN8BtpnjjJw+7SPrD62pNV5ozIn8L+bz29EJJ3BjRMFt
         fp/jqAxIZ9c/Y969IwMOynEuai0g3fiM204d74V0uP4KmjrtUSTpDGzDU2hsH3tY4P/S
         mZ/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=a9SCF0Kr;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id b19si110345vko.0.2021.06.17.01.41.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 01:41:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id q25so4428841pfh.7
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 01:41:59 -0700 (PDT)
X-Received: by 2002:a62:53c4:0:b029:2f1:8ddb:5918 with SMTP id h187-20020a6253c40000b02902f18ddb5918mr4111731pfb.80.1623919319120;
        Thu, 17 Jun 2021 01:41:59 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id a9sm4338743pfo.69.2021.06.17.01.41.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jun 2021 01:41:58 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: bugzilla-daemon@bugzilla.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [Bug 213335] New: KASAN: vmalloc_oob KUnit test fails
In-Reply-To: <bug-213335-199747@https.bugzilla.kernel.org/>
References: <bug-213335-199747@https.bugzilla.kernel.org/>
Date: Thu, 17 Jun 2021 18:41:54 +1000
Message-ID: <87mtrosx0t.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=a9SCF0Kr;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42a as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

See https://lore.kernel.org/linux-mm/20210617081330.98629-1-dja@axtens.net/T/#u

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87mtrosx0t.fsf%40dja-thinkpad.axtens.net.
