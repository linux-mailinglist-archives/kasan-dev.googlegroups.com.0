Return-Path: <kasan-dev+bncBAABB2USXKWQMGQEP2EWHTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id CF3AF83681C
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 16:27:40 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-50eaa8ce853sf1305120e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 07:27:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705937260; cv=pass;
        d=google.com; s=arc-20160816;
        b=FZjBw9q3LF/DHSEi8qkopVJgt6nXpZ/bjQEUw4nP221OJo49LhPYB9IHhHBdFZlrap
         WRkN08DX9vOc3OQoZtEPifdWUNodUQ0Y3hYzypBWJyicgyAO4Zel6u11qBTsB0BhtctL
         4rh3rAUqOyOQTa4Jxz10k9cz0nLawFaLa+nDQqtFEfMN3HJE0PZRUoSZdA9J1E7j74O+
         kdpMfhW0DOgAgnjXYB2L42rfNube6IoWu0FWajv6o89K1BH0IZZZUONVLZJSryoMlb/6
         BoB7TGlz8avgMG7fAMNdtGb8vJMcNmULnvqIVwohkBOukvTxxFowZmDgvzKnWVN1RnSC
         ypJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=MVa20djCmJmJUBUqykfbzCLWxAVlTbbQ7Fhq2m5T7Ac=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=E4pU3xLlEHRFVral8smT8jXDB4lf9qS5/bX66fiCTt/gnRRYAj49j0YoW7ZFv/lWBh
         j+COfxrRx9bvNk5tDU3LADBzXI8T0DBHAi+E8sKDE++VQS6GEd3tTVQsbAd+CXZ7YYCh
         Hep1qo7IptK2lA1MipPiCwebbS5O3RmE0Lgyi6ecYpFx1BlR/0Uf64l07x8SWDzRDa4C
         JS+qRZsuQ1Z4aHj+WG3slb+ZpiKYogMbbDj39+OXOdJY/OdaPmvKl+cL5FwNShKSr1wa
         KsFtRdSvzekoKrSS3EeUb21QgEmQ0QHvsmRlvlHfGmja1rxD2eCDEhhsRgyzDm2SIoxw
         FhCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DE4LaCzH;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705937260; x=1706542060; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MVa20djCmJmJUBUqykfbzCLWxAVlTbbQ7Fhq2m5T7Ac=;
        b=vKJCL+WGo42f5vhYSFGUeLJ1ftTrxFuf/zjNKTGmidOFRVL1PqJMjDJ4G/YA9gEFjl
         7gzLGT/1tKCBJEnkcbY88n8neLt4a9RgrUkyOWeH7FYJjCmoArcF1lHuRFiQkPwDPECW
         e7cAc/pR7Yc5ql2wHasJfW/PLpgSVvrl1bBmSKvGb7i2OCu1jvij/wE+ybyrrdNnbEvF
         3SZjLs5LncUGxUGjMsBqRmD2kjBdG8wPP89/fmZRsvNRuLfiwcFAa1uwijsONrG8y/+7
         phUXtpXiFZpu0vjyEssijGxIGZSbGHy0RTzg02wadVb2Dl8AtjKdp/McHC5ZxWgq5JFk
         2mtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705937260; x=1706542060;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MVa20djCmJmJUBUqykfbzCLWxAVlTbbQ7Fhq2m5T7Ac=;
        b=Sy4IaoujBcaAv+8Jcy1vDphXo6lo6tXvRDJu7ciDLc9WiyHDvsmaPjHxGrfGxXrdp/
         PYyvbW5gIlbq9wsLa/+oecJu1J6t1i9uqJe9IiLDoNnrqFW8aag4OTBwRr1+qX0cxIRH
         tmu8hG1TFN01rrqGgy1rpEjDk0xKNAhG5BSM7rObC7JyBypscfFNjM16cysGj6pZzBCX
         g1T5uW4VLvGWDxQ37JAA8ZH7EUUa5tEc8CjjwvLBqxXxwmx4L/ublI2JeELFkERXHgvn
         zEaQXpDsMR/z0Za5oJdv/WtidppdBE1ij85U9+O0aNyHqWa9m7nvE30YpKDRIkTgOmED
         9iKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz++Ftl0/Jv0qIYhEvsK/tIe3OKd0XbM/3sI38sMm+QG/8+qU2H
	nmJpTJLSTuN+sohHM0/DUlh0VFwBqJWHRp+RihhzXFtW6tQJ0s0twQk=
X-Google-Smtp-Source: AGHT+IEs9GRHv27rqre0Y0xMm2ZIi8znv/agZOK4cK5Ui9X/Vim4M95Ykw4VyXKDS4I8DUoC1gNgRw==
X-Received: by 2002:ac2:5051:0:b0:50e:9354:c36f with SMTP id a17-20020ac25051000000b0050e9354c36fmr3344198lfm.19.1705937259163;
        Mon, 22 Jan 2024 07:27:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3451:b0:50e:8ef3:e089 with SMTP id
 j17-20020a056512345100b0050e8ef3e089ls121910lfr.0.-pod-prod-00-eu; Mon, 22
 Jan 2024 07:27:37 -0800 (PST)
X-Received: by 2002:a05:6512:38ac:b0:50e:ed79:d94a with SMTP id o12-20020a05651238ac00b0050eed79d94amr2192788lft.30.1705937257337;
        Mon, 22 Jan 2024 07:27:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705937257; cv=none;
        d=google.com; s=arc-20160816;
        b=UkFJpfmHaef3luH8FbqA/c5vO1Ox5jgutTNlDDhzrDZYKE61be5/HRIY4TQ4yxIm4k
         oPpZlfxbfJRtWpde53ojcl6AbaHYO3qeZiac2TJUkld2XzdNGbWrUIierWfzq1NrB02u
         BXA0DM/1OZ6XOWvgYv4q4Wkq5kUMiSdi6jBAwaweYQeC93+Ckn4emI7GJGj3Z0ONaNF0
         aNt1GFbwTvTdW/Cug4cXlDmsPlYfYZBAYpoMt0eoq0Q6JD6VLR70WAoGwQWC0CKLy96L
         L+K9E4+xwIrKrwnflRNGJUfWm4eoqkU4W2b60woKEHyE48Bmj8U2H2qWloYVK1X/zZQ5
         OHvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=WBx4Fimtcrli3kdlZVIBBMDRxdwVPAHo9xOV5+Mtxes=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Gzh2rXMuQFnrMA21FS6zUU14Tb2a97zu5ejNDhUvmIhDQdftcN1UQE3oocHjnE1/Lx
         NFR0/k5GDw103uzi3f94o9SyZTRcmrhozC4An41ANuEFlnZNnUzyAH8R2U9XbzB2s3ma
         +itR+LB67yvwq+T58S9NGo5ygjAXnUuq+fWI8I2PtwmONX7ZUc+7dAQu4Gj7/1WXcQPK
         74AXKfUUEdbXksywr7+66GQnZPtbdUTNsX0grJkOuGyFMeeSzI+zMBhubfE6WMZj+7lq
         tc3W2/MnBJ+Uu7tXOrLIduax//s05E0AriR1sSidR8Qb49NQZGskzb1/1IZaH+Uyeusr
         d5Xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DE4LaCzH;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id k7-20020a0565123d8700b0050e7813f310si403652lfv.9.2024.01.22.07.27.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Jan 2024 07:27:37 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id AE7EDB80E98
	for <kasan-dev@googlegroups.com>; Mon, 22 Jan 2024 15:27:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 5DC0FC433F1
	for <kasan-dev@googlegroups.com>; Mon, 22 Jan 2024 15:27:36 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 4728BC53BD1; Mon, 22 Jan 2024 15:27:36 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218313] stackdepot: reduce memory usage for storing stack
 traces
Date: Mon, 22 Jan 2024 15:27:36 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-218313-199747-SNINduDXgK@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218313-199747@https.bugzilla.kernel.org/>
References: <bug-218313-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DE4LaCzH;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=218313

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
Eviction makes sure that we save fresh stack traces regardless of the uptime of
the system. Without eviction, we stop saving them at some point, so we won't
have stack traces for bugs that were triggered a while after boot.

Re memory consumption: by itself eviction does not limit the memory consumption
indeed, so the idea was to add a command-line parameter on top that would limit
the maximum number of pools.

Re overhead: the idea was to use sampling on top to limit the overhead (if
required), see https://bugzilla.kernel.org/show_bug.cgi?id=211785.

With that said, I don't mind making eviction an optional feature.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218313-199747-SNINduDXgK%40https.bugzilla.kernel.org/.
