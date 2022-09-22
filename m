Return-Path: <kasan-dev+bncBDGIV3UHVAGBBZF5WGMQMGQETPFHESI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 741565E6348
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Sep 2022 15:11:01 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id d21-20020a2eb055000000b0026c5313dd58sf2977743ljl.9
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Sep 2022 06:11:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663852261; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nm1Op0tmFDzI6AQja68Jr3wenh0ApWw7IC3GYasAxF4iw8UZX6+iv0E65KKaawFGIb
         CMhPwv36H6cMad+1YoABkO+c3Lmc9sqDe+46dZSfaywBZPO+S725HnZu7/5N1LETU2O3
         LZjs3dZS8XqbajLqYhLnTPELHfyznxHbYM6EDLJujZqNhgPUYelbqaS5UQcCXV+cbrRO
         5Qx01k8eqB4Bs14Bm94k5/rZLVg+E3u75WzEnljK98E2Pz2PazHoxsqdYopqrTpYe4fh
         5Vssn0eAocLP2MIgoxFNx8KDvOuGb82J/L9CTrfVk1P6d0sot6bIlcVVXVDOoA08x2Kz
         1crg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=caWCzQ8du+QytX/O1XyLfnjBrfBe/GeaQPG7vGwUmaI=;
        b=IzHiV8PtGsm6Cw2tTWLO3sDKi9NZxN+5DkZ20Qu8+724Uk4/r+Bym30p/N9lhR8UpU
         /5LRZ9UjyWD2BHMF7ISeyjyCJd7latpMcLcEHbVFV4kMPUOP7Ykk86sZGTQ3xOhuftVQ
         jxrg2IR1LJ/wARn3wW+Tth30XC2UyyAUcdYNt235S7ndf2djOL/BZI9nejnhxWd9azHH
         m5bAxtVRkCmxyWjj7fND++1DN3hvL4h2Q1CYNyK6vJAzQnqJFYuz8j6CNi00DlOPtAns
         zf2XY0pAuajYmnL737fvk9lyo9DTfCbcWb6bdXlvDM/BSznbT0unofu9wCTcWFJ5h2X/
         MLPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=MyNVPihH;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=caWCzQ8du+QytX/O1XyLfnjBrfBe/GeaQPG7vGwUmaI=;
        b=CXfGHph1VUt8yLllUO4KN2nb5GcEG9YcuBp1GXzIRqB+K67vPxJAAB2tWet9ENJX68
         OAEsLXskgkbIhawNaHEYJUhrnpXKEUTosoIDsg3rXy0U2elSjYocRPHVC0jAZOVWs+F2
         5mkVVG4hF+ROBukl3Vme7LHsHwwSZwUn2faXDVHK1+eoB/9YSoHTanGqv7Z2izDCiOIx
         gcghG8aSd/nAWjTZneJ729ratWTpUzc97v3IBp7d7h2dJHuX2pzDbpNs0G6QJ24fdyUb
         UM6ClLrqgxFtTTnyGMDlC7+r95evit412yVjyh0dzJ8X+j/WPYRxovurSMB744Q4BTq8
         C+lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=caWCzQ8du+QytX/O1XyLfnjBrfBe/GeaQPG7vGwUmaI=;
        b=W45Cr8IjJvnzOr9lbEUR380B0kFRG6osC7+CMThSHhXIsIj7ccRlI4Uc4RVaTgi302
         5k9dUnMRfDt7WnqoNLuJbzcZlG8/j3KV9nA6YyejqLFaw2QfPMA05ZEKrWV9/Q913jjk
         jLL4+Thv+0oLI0EYNdie5ekIeYmzVRuXOfF93dXZdKIrD7pIJ717LXoYxJKVO/U5xlc/
         XDy8yVxDwFubuEnjwBUOkQe0j7yceg4kLHviPaZdt5dZUCqGSuJ/f58IUZ3gjnAL++JJ
         2ZJfk9bQ3giIkFFjoV5P9aPMy+pR94B/RF1SxhEaFooRsZx+V1jXlw7ElOjWAR0Taxag
         HggA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1ohevx+0fd77WSN8al0WplFeQH7PWJOcmBUxrqYcvMsv1NVUDY
	x4FLf9pcLvJ6LT3j7yJyMk8=
X-Google-Smtp-Source: AMsMyM7eplv4Z+fMLtkCw4EO9KiKwOK8Pocf6/OKOI3p+EVEY/JfavdKRG4Dr+aWWL+5H+wiWsm6lg==
X-Received: by 2002:a05:6512:a87:b0:498:fbeb:daea with SMTP id m7-20020a0565120a8700b00498fbebdaeamr1315931lfu.632.1663852260617;
        Thu, 22 Sep 2022 06:11:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9ac5:0:b0:26c:50e7:2c36 with SMTP id p5-20020a2e9ac5000000b0026c50e72c36ls1847558ljj.2.-pod-prod-gmail;
 Thu, 22 Sep 2022 06:10:59 -0700 (PDT)
X-Received: by 2002:a2e:9b17:0:b0:26c:4ede:512c with SMTP id u23-20020a2e9b17000000b0026c4ede512cmr1057030lji.529.1663852259449;
        Thu, 22 Sep 2022 06:10:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663852259; cv=none;
        d=google.com; s=arc-20160816;
        b=QtF7gAvEYDOdAbI1+dwDy2+U0Tpu064h0vxM9azSCFv7APSCtB/P0Swx46d/wqE1RL
         lRHH4VXsJLGAcZgY45kt4HbwPj2qnwVqQIKcTX6xEHsTSmEuBJb0cU3z7jsmCDRqNXLo
         5P0ZvxpQlcP7psEtniZO1A3Zhw/LxzqA3/1CoYc+IFZfZpUyiDLPcjGv9opQ2hYn0vsL
         qoQ9nWdfcWrur+oEFaCtQ6JN0BDe7r/3e6VYzWz63m1Kdhzjw0CgipWP1z7g1ia9poey
         6vHLCTp5SrlokHjSFKExQ6n9dxn1NFt+fqeUSpBp8Sew/1UErXJk7YEgRdFj4zEBw1yY
         mnFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=yv6A/76E+tltxES5+4A1FaT9rfH7150YgXq7d8On6NY=;
        b=agH6v/Mw44zI19+4m8CphLf6CQwIQoz1tNkjLIa9hA/gROTzDba1V9my5H9iA41jxB
         9ZRGojkHd8ytJ+4ysSeo292mdmhNVr/fiN45Tw3Fpkg/mWGg5MZOh7RNcuy7rFsFXk9W
         0ZqXFPXx2TahHR+tP30iLcOM2VQJtArKw4KpEV8XWflysfAzkr/XE1cJAUzlDGh7LlnY
         BvIPbXJD/lhe60Q0uXYJV6aT7xeLHNG3d4EslI+JHHgZDBoYKJwrA/gFt4x5LCuq3m12
         hABUuE4T0jZkgKnDhK9z2E+BQKzBhu+W2zBiVbxcx2bgTTeQbxDMgD+DmqmbiAR2sXWj
         l6MA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=MyNVPihH;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id be27-20020a05651c171b00b00261e5b01fe0si194103ljb.6.2022.09.22.06.10.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Sep 2022 06:10:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Thu, 22 Sep 2022 15:10:57 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Chen Zhongjin <chenzhongjin@huawei.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	liu3101@purdue.edu, nogikh@google.com, elver@google.com,
	akpm@linux-foundation.org, andreyknvl@gmail.com, dvyukov@google.com
Subject: Re: [PATCH -next] kcov: Switch to use list_for_each_entry() helper
Message-ID: <Yyxe4R/FkWdjdwuX@linutronix.de>
References: <20220922105025.119941-1-chenzhongjin@huawei.com>
 <YyxR2ErlHj6wrR6m@linutronix.de>
 <316fc8ae-b96b-1fb6-4a24-b8bcc6f8b948@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <316fc8ae-b96b-1fb6-4a24-b8bcc6f8b948@huawei.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=MyNVPihH;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2022-09-22 20:22:19 [+0800], Chen Zhongjin wrote:
> Oops... will fix that.

Please _never_ again post patches without testing them first.

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yyxe4R/FkWdjdwuX%40linutronix.de.
