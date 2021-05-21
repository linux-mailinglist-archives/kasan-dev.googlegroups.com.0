Return-Path: <kasan-dev+bncBAABBJOCT6CQMGQEE4LWYTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B49A38CB17
	for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 18:34:47 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id a24-20020a5d95580000b029044cbcdddd23sf11297932ios.13
        for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 09:34:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621614886; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZljM0S7EG43tVxQEicexLDzSDwhzCszYNfzytX8UsVLbOfLFbSFWeUZYnI1Ilbh7AW
         EZO7x6GmYh3r4Ee7PNMU8bBdYWa7fFbZ0HnjBFF+1aVI65oTkhBDvqcxm4+/Uo4x/kBQ
         4BpQgGIS6OoxxfVn33PMtUmdWEMRL/1Gwg1HAbz3mMdovEMm/hEUQjw47bZBUdtNElsp
         36eaa0Gyh2rGS8yygIndVfOvffygLmdcXsmvyKETwfrIVmoUqpCghhQrsRdeuiows0VL
         EJpSoUSWibznP0Su1S2zUCRhtCopBeXSEkaFsu6eqsekPwV9jsHX8e6C26EJNk17wqqx
         vGqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:date:message-id:references
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=qclWBBx+wHjgrCnd4Gjb30hjgPvtDMS3dUpharmysGw=;
        b=PQXzcxvbOzym95R2fxGaw1ddl70PKtTo3IJHQx565//OLhW6WEeXWcF3tj/l8LYLlK
         ZHo8VBMve/Q06pMBFBsKBWILB2qR+9v/pVZbHNb39Pf84QB+VHsSwOnl6AKyEeym/E79
         NhagBygQG8Tc+0csd+DP0qWuVeqMXoLRj9J9FRVnY+WFXvVAfJxS3ow/GL6XN9kKRLHg
         Ybre88nNcJoYV4EXc4BIDzlNgfsK/uzqF2tKUqT7wyo+PycG0krnVEs69likHZ3xXpbR
         hqyN9QVgjnXaJso91t5mYJ30fXfxeqA5PpJdpqDYFEflzgnJkFIsxDZGKhxwzElA1ah7
         T0Rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kljIal03;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:references:message-id
         :date:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qclWBBx+wHjgrCnd4Gjb30hjgPvtDMS3dUpharmysGw=;
        b=KBKm4HfNBOPdSFcY49WfM7JB9WxGptkIgtVv3Bzt4Av0bs10/rdX7epyaChGv85cQp
         g2crkITM8HBy/zjXMA/dev2rrA/JHKozt11uPqVr6OWJIoJozByfUugDyz0q47bn3PsH
         IshzX2e+ou4pGn8OC5Qyph3Zy5esfwSnXAfBPwJCOMFDlPPv2Rqs4AT5Yer43jhqPPm3
         te0cC9NiaxCo4O544e2+nxfZIdK3mZv9LNJHoq/u8q1OEcxzf5ZFGguSs5KK9S1bl8Ys
         wJifh2Gs+lZV0NJ0tyj0I+N8tTQntClujPUiQBCLLvYVmsP7+yqmkUtQXMV8MLM9tifV
         ytfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :references:message-id:date:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qclWBBx+wHjgrCnd4Gjb30hjgPvtDMS3dUpharmysGw=;
        b=d6H/oALG9B/ZrddsjiA7WG0DRzN02S1sBQKTo91Ol0IEdY2RAWsjsaC+yeM/SoqQv3
         bGYuZqVuXE8jAdlkIfbBmGDsoInCXAoX+/qrAb4LsAnK3kgx1byvNZWb1tDqmeD5BAhI
         ixBq/c/3b6SSdRr7N5kdeDAHXfgZ3ySbpdy9K4iIbo5wTQ4JaPLssRJxOpq0ZA46zr+k
         vuQO9arg0YrjEDAy4rb11mYgT2cQWJaJAHlI1WkJkKA6Ieb6Vs77wxbtRN8vsA4Iwfpq
         j2ut6nE+bDbQ0pGJv0+ivDIziiojhSAIuNi6G3OOH9LgORUb49v+7UFzWUJfSjbvsWqJ
         w4OA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xFYmI0btITAHjSl1HkXpsHK6ollewDNQ/2B0K9jndMI5AKUVu
	rS4nIpcGGXrQZuYn5xhQ8ok=
X-Google-Smtp-Source: ABdhPJzKIOMF6gcUKxlPNBMwUclJEnY8yfbui+LTKINrXvkw/pjKZfp+u2NjMUQIvr6Sm5Bs1aFWqg==
X-Received: by 2002:a02:bb98:: with SMTP id g24mr5775329jan.19.1621614886054;
        Fri, 21 May 2021 09:34:46 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d852:: with SMTP id h18ls1660485ilq.7.gmail; Fri, 21 May
 2021 09:34:45 -0700 (PDT)
X-Received: by 2002:a05:6e02:527:: with SMTP id h7mr12904129ils.93.1621614885731;
        Fri, 21 May 2021 09:34:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621614885; cv=none;
        d=google.com; s=arc-20160816;
        b=q15ospv1veztxW5u7FsRGUe1KoYsRtzkBHMRwYzdcnKIHMX+lpSoDb4DKA5WFa0pom
         g8SfERfexgAYoukoky383iuRgoWa/qxkWGOlvGtH9LFbaY53hkuXPSjbfEGnn+m4Kw+U
         obtwaJIbPZMuHde34bqXKH69KDYdeDWYmMBn4G5WMfbc4hBUGc6Sdx1d1tKVeGCVocww
         gqbnlK1N/I58WaNHL6xObM28Z/di7oTFZy21Wi6OGADSA11xAcxxqEgKk3TXzDDiZjNq
         Mjts2noiZSek3W+Syd8Q7SGWwixlmtJrXBkalzliUQ2C0w3e0SCpbTTygOHLRI+1v6re
         I3nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:date:message-id:references:in-reply-to:from:subject
         :dkim-signature;
        bh=mbCqt7ZkUu9HurSSfA6vfSQlKhJcNFpCXqPVahXSO4Q=;
        b=lazWBFQLOyJhmbRi4YIDP72iokuAMeiI+QkehERghOMkthX74/uJvcmAbdR/eCo8kx
         GYk4ZC3cmSWq75UQA6wQ8VM4hww9dZj3iYehJA/cXX8O7UQj0vn9aKJRTIOr/50uPcBS
         8uTkWH4jps7l59iTCipffiwIA4VnzJZbfvqBLjf8Lk85zRlqlA6pTUe8XjqH/RcIGhN4
         4TW51oxK00ZXOc+UAWIH2059ECgbkMkNoNBz+Lk0stkCaSC2qLW5GgtHiHBPV5YKHflO
         manzwPhzRamS7W1TmOIjMWdBCTgPFdXRnDqKbFR+XGQbrvmT6PAd7nxKFO5kBzdlZ3iR
         kwUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kljIal03;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r20si933180ilj.3.2021.05.21.09.34.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 May 2021 09:34:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of pr-tracker-bot@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 1F0E1611ED;
	Fri, 21 May 2021 16:34:45 +0000 (UTC)
Received: from pdx-korg-docbuild-2.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by pdx-korg-docbuild-2.ci.codeaurora.org (Postfix) with ESMTP id 0D6436096D;
	Fri, 21 May 2021 16:34:45 +0000 (UTC)
Subject: Re: [GIT PULL] siginfo: ABI fixes for v5.13-rc3
From: pr-tracker-bot@kernel.org
In-Reply-To: <m1cztkyvx2.fsf_-_@fess.ebiederm.org>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
        <m11rat9f85.fsf@fess.ebiederm.org>
        <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
        <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
        <m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
        <m1r1irpc5v.fsf@fess.ebiederm.org>
        <CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
        <m1czuapjpx.fsf@fess.ebiederm.org>
        <CANpmjNNyifBNdpejc6ofT6+n6FtUw-Cap_z9Z9YCevd7Wf3JYQ@mail.gmail.com>
        <m14kfjh8et.fsf_-_@fess.ebiederm.org>
        <m1tuni8ano.fsf_-_@fess.ebiederm.org>
        <m1a6oxewym.fsf_-_@fess.ebiederm.org> <m1cztkyvx2.fsf_-_@fess.ebiederm.org>
X-PR-Tracked-List-Id: <sparclinux.vger.kernel.org>
X-PR-Tracked-Message-Id: <m1cztkyvx2.fsf_-_@fess.ebiederm.org>
X-PR-Tracked-Remote: git://git.kernel.org/pub/scm/linux/kernel/git/ebiederm/user-namespace.git for-v5.13-rc3
X-PR-Tracked-Commit-Id: 922e3013046b79b444c87eda5baf43afae1326a8
X-PR-Merge-Tree: torvalds/linux.git
X-PR-Merge-Refname: refs/heads/master
X-PR-Merge-Commit-Id: a0e31f3a38e77612ed8967aaad28db6d3ee674b5
Message-Id: <162161488499.28405.110780038136430578.pr-tracker-bot@kernel.org>
Date: Fri, 21 May 2021 16:34:44 +0000
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, "David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>, Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>
X-Original-Sender: pr-tracker-bot@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kljIal03;       spf=pass
 (google.com: domain of pr-tracker-bot@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

The pull request you sent on Fri, 21 May 2021 09:59:53 -0500:

> git://git.kernel.org/pub/scm/linux/kernel/git/ebiederm/user-namespace.git for-v5.13-rc3

has been merged into torvalds/linux.git:
https://git.kernel.org/torvalds/c/a0e31f3a38e77612ed8967aaad28db6d3ee674b5

Thank you!

-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/prtracker.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/162161488499.28405.110780038136430578.pr-tracker-bot%40kernel.org.
