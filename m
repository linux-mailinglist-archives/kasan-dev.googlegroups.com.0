Return-Path: <kasan-dev+bncBCT4XGV33UIBBWP6UC2QMGQEIKYQMCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id EC83594034F
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 03:18:19 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1fb44af00edsf662675ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 18:18:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722302298; cv=pass;
        d=google.com; s=arc-20160816;
        b=QT8ruxRL+kXKO0TWfGXzTAg3xZJk2I98kOGkB9BWwA1IsgKDoumqGNLFtAEytqDpvH
         WqGZV7fsXUB7DjzOASQt0O2V3knmyoB+dtvnShPcC7UfIohV13+xU+hwgaiuuZgAVkzN
         QnHEwDfosg+979eL8yw1y0gX012Oyr5hW43b/fq44PC+HBpPIztIsDa+3kq7SDl61ZH8
         prPIdo3fCYt0p662D37zvVP4aGARzXfX52N4d82rRlb9kdguPAihs/QS+jcwS4BwAZL8
         8EUV6l3hL+9zqTqwiyUH936DAfRkVyA/6ARla16eN36xCtvZmSykZG0ZX+iSL/6AAq5a
         e+Yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=dhX+s0f1YERqPIdUzpOzl5FqnJOtuuye5rIn7KsFZLk=;
        fh=mBmf1SVUM1yA2pK1Odv4F3SAXC1SMU2YLuTfRkGdSis=;
        b=OSlSwKn+KveDFBSJOv+P8YHfPLpdnfMc6AV/+69Kl4w1tR0+xfFArH+lVBkjywF0UX
         1muWHXg2qrAvBPukatH6xZ+L2Wn3tbXV3RYgZtk5w95HF+NPf297frTchvcc4+wOnJbs
         IdxIUeaaOoeQhAnqYIS/VsZUZeYJSAw7dKq0HdNgm1kA5DZnX5uELjFPxfm4Lw9tSwe0
         VJp+FWwAqqb/UwGCMIR1Ho1ViqlHNQMMz/2ehO41l4m28ZyqL57GpKBW8A3pHOgCpm0x
         rMC2/HymYqUnYu5ErzzHOfZaoAEPouJI7SKGJ6fNNk10t0Xcu4BXrRIF5nqw1Ss+HSLl
         wkBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="SYSEbb4/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722302298; x=1722907098; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dhX+s0f1YERqPIdUzpOzl5FqnJOtuuye5rIn7KsFZLk=;
        b=vKJTH2zamMhxj+6SWPDl0/c6D5fGW3NcIUBFMsh9dXqdV8iwzin/497agTksl/i/fw
         7qb3I0Vj4bFjT9ssmWimAMoLZ0fV1/IFaXocLvNZp3cE5YQ3L309dZSRXgMe4OssftYX
         XYuc9Rk2aIAh3Oe+Axkt3JbHWvD/z2TKNmW/xhkw21iuwDZ+XrHt1eZ6MJ0LgvBOCnlB
         7q19jjCYcMxPyzuSogaMMa+inx9SsfWBjTE46d1x9DrTG9vMpl2wefntjEG+e1m8fhGj
         eRmHEyB+Ej0RCZL8GinE+I19ovWu9rX1c1JugXHpKoV4Zt8C04EcaVTob75Y7GKCANrm
         PsvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722302298; x=1722907098;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dhX+s0f1YERqPIdUzpOzl5FqnJOtuuye5rIn7KsFZLk=;
        b=oT1NFGtm/1Mits96GMLWeov+2p1Ts+DekXDsi1G7fB2eARmSTczwnpITgBCXg74d89
         eWAq9SHdNZR2dtAGbnhbHj3iHJHYwul95NYyJBnDp9e+fyT8iDWV7Ik7uyRIQgKMHc16
         RvQ85XqE5zFqB72RR0hqBefa/FYm8objLTWRPQWCFCOZlQOdP7nTobZbGmrYsN0UVhhP
         7kJ38ZrENQ/7mPstnAsWGUFYMEbcJIgWODYsiNFpAN0bJTxciiA0MHTcX5OvzGau6oAG
         zkbwtB6A8wIoBuTPjNMSEKpV+Ik+DyDJ0WDvjoVF7o45zrLDkMgwXfpAFX2aEtxlYa/F
         rYXw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUMyTWfL3kPTHFxmXcjnu8GAinvohy8Y0uiBg5d/VLyQ/ahUzf+4QHBC+LewZuuYQLyKpI5gsOJPxCgfW9RRF7SZi9O4/Fq+g==
X-Gm-Message-State: AOJu0YzvZ3e1ZS7G4QdHC4lCqBbpHIk7hMlJT3JpueHP1PgV9Lguklnt
	MEe5zeM699liA/vSJ/mW9KopkXZFqIc2kpxkIW9mgMAwcLx8CLRf
X-Google-Smtp-Source: AGHT+IFupOTp5s+ejNQZ0t1Z1ApAQSV58arJaUld2+oewpSXIddbgXwh7fp+sOSxgYQUrpP1LMw9LQ==
X-Received: by 2002:a17:902:ce83:b0:1fa:f9e1:5d29 with SMTP id d9443c01a7336-1ff378d65edmr746695ad.28.1722302297774;
        Mon, 29 Jul 2024 18:18:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:2ec3:b0:2cf:2b3d:c788 with SMTP id
 98e67ed59e1d1-2cf2b3ddc02ls2282751a91.0.-pod-prod-04-us; Mon, 29 Jul 2024
 18:18:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW/VC9Ail9kfyKvYeNPn+fBGCzzDUAD5aes8w4CFzUWyyql/IDfzT19TrxlTX7diC2gFHmtBhNbNU3+Cmf7B74BTFKEjVkcFe/qlA==
X-Received: by 2002:a17:90a:2cf:b0:2c9:7cf1:83a4 with SMTP id 98e67ed59e1d1-2cf7e1fa01cmr7439885a91.20.1722302296329;
        Mon, 29 Jul 2024 18:18:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722302296; cv=none;
        d=google.com; s=arc-20160816;
        b=Fabk8Z/RvRWBx6HpQtWLGRnlbvXafdOQ6JAyftOm160uaIXll3UQQTmIOQWKECjuXH
         VAs9bwZ1MXxg/rGeJ6OsYlGoCQUXw4SpeOxS3gDFv3HmVn0z7cJ745RDq0uCt/w5sOQR
         YjpN6Fks93yCTvG0VzsZK6FHU4hTk+pUwD+YqtDGv4gi+2+p0Yi/eySl5Fuad9GXtkJk
         rWirOPso6rdyfUZnMwx6dneP4Ohmfi13jOSUR4Pdej00dMwFT4T6iD0AT1u87h55+oZ2
         v7p1TVZKaAp0K3Dm0V+sI8qvqwRTcqAvz2p8tjX97KIIzsQ00zPLf8ezT6z9NsmL1+6y
         Xqzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=bVQ875/dJ0RXKRoJFFYqDqjmT13hqOwDybSWDBW8qGI=;
        fh=zQzEkivPCDvGuo58k8Z3UQzmeXHg9EKQ0QZQBUeQ2M0=;
        b=JlBHDa3PIpGeddyFnEmMQXxWklsIG9HOY/xQWTUC2U3bmZ6Sn3Zi/ZXSTWuJiGZrZw
         VWVOZg+JbF3YK/6BemnbJUFLV8rdJs5Ot8rb9nid+xKQjl4WK06nnss0/NkVvuPSM+3L
         aER2JaVI82SMWF8uwrNTygJMUC+z+afV7qbkc3IvS+rYkHohaQSmDFRQNtK15HoHIJTj
         vboD0PHSnsb06ahmIEG/mJbRIc3cmNWxWsQYH03zM1ib3O59PisTWcu3ahHfgkWsIQdo
         xkQkDvzvta8FT92Wv1xAD98B0yY3Ar7rkYDIjsIWpDQTATFHJo2QoFwfViB5247/0EKZ
         WT8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="SYSEbb4/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2cfca2a671fsi64601a91.0.2024.07.29.18.18.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Jul 2024 18:18:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 610FC61C3D;
	Tue, 30 Jul 2024 01:18:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A50C6C32786;
	Tue, 30 Jul 2024 01:18:14 +0000 (UTC)
Date: Mon, 29 Jul 2024 18:18:14 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Huang Adrian <adrianhuang0701@gmail.com>
Cc: Baoquan He <bhe@redhat.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo
 Frascino <vincenzo.frascino@arm.com>, Uladzislau Rezki <urezki@gmail.com>,
 Christoph Hellwig <hch@infradead.org>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, Adrian Huang
 <ahuang12@lenovo.com>, Jiwei Sun <sunjw10@lenovo.com>
Subject: Re: [PATCH 1/1] mm/vmalloc: Combine all TLB flush operations of
 KASAN shadow virtual address into one operation
Message-Id: <20240729181814.8caa3db2186ff88dae1be966@linux-foundation.org>
In-Reply-To: <CAHKZfL3YsfSLfNq268p+bikzgwvj+Ng7R09cZQk16aKio3fViw@mail.gmail.com>
References: <20240726165246.31326-1-ahuang12@lenovo.com>
	<ZqdTK+i9fH/hxB2A@MiWiFi-R3L-srv>
	<CAHKZfL3YsfSLfNq268p+bikzgwvj+Ng7R09cZQk16aKio3fViw@mail.gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="SYSEbb4/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 29 Jul 2024 19:19:33 +0800 Huang Adrian <adrianhuang0701@gmail.com> wrote:

>  Let me
> know if I need to send the v2 version to fix this typo. (Depend on
> Andew's decision)

Thanks, I fixed it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240729181814.8caa3db2186ff88dae1be966%40linux-foundation.org.
