Return-Path: <kasan-dev+bncBCQPF57GUQHBBPGHU2QAMGQEEZH3WMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id E66A96B1FA7
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 10:15:41 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id x21-20020ac86b55000000b003c01d1a0708sf744525qts.19
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 01:15:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678353340; cv=pass;
        d=google.com; s=arc-20160816;
        b=YskM/nD1lz9+tfp2jSe2cFi9XBi2lr8CydlHHBZUpmNn6fFk4Ajhs7Yh8CSZf31RqU
         N20wKACRzhjBytch32wsb9kH5IWj9podsG2NWFZ/WDUjmrRATnxw7+77EV/MzKvVR4aa
         c5Ceo/1PKkFuT7ByRQFDzMdRw8U6SM/+k0Awt81IDya5QYCazbOyxz35xBC2npUeUQ0g
         ORTJnocitC8PvAPPAtg6TChbo/RI9n6Kj95GSSOaW95ubfvJ2qw1gy+4UXx61nElpLJI
         kwHGXXjBOU46W1+1s4mCT4c4W2D/S2SHI/nA5vme5rIbNvKaVfkme9aDrx0uF8x+Jju+
         isUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=gRoyNf3kCSjJAS1UGGXCPrCbOy2Aux6+m1q9y1r3hDk=;
        b=sdA77+hDvCNrmmy3M1hBkOuhesix16KE/sG8bcDLY0Pjuv/Uo1rwDb2IFxyC1M8Inu
         3mLuFDTXBhTYNPSrCNdilDxZ2/y432uNWZFSzrVZVrUyyLg4sydv2CMeWpIgtboTiM4v
         82059yITxOExBYqGFo5LezLYy0SAxRAS3eh63U21+q1bxgP++/apAt46ZGDQCmaxvNR4
         /LIXY317x+bWiQuEbAPOjaBeXz/T4VEMYG0K82b9yovHBqkqIAeq6jAlo9nwiBL2o0vW
         Zg+JYS9CPiMB+6cepL8iYCgRi7BjPqfzNgcaG5x1hnZ+w7VXzKG5oYOINdsxvJkYN0LM
         losw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3u6mjzakbafaagh2s33w9s770v.y66y3wcaw9u65bw5b.u64@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) smtp.mailfrom=3u6MJZAkbAFAAGH2s33w9s770v.y66y3wCAw9u65Bw5B.u64@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678353340;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gRoyNf3kCSjJAS1UGGXCPrCbOy2Aux6+m1q9y1r3hDk=;
        b=gtdLs9wns1hw5uIxuA0lFlzjeiA4+n/EcnfJWtysyNWyAztV/AgRDxjvXGTIxIARDL
         78u9rH/TLlcKYj5tnPq8/O200WCWiYrDQV5qTA6En7s0QRszhCdjoroUtYZARsSJEWTh
         eHE4XIUGSZVn7zaahPSUaqmlU2pjveCbMHr7wQ7hwkOvfgTrvQvx3YDWpLPE61qJY1v+
         MBKnj7LvMQ8bynJ+Ynd95nIToPD5CjEW8X27pZWqxHbzk7tYkeq3Q3jPBmAdFbYCmNFq
         8G7aeImlQlD1F2V50981dE9U3zYN3pWLowUAgGX1fuyxaWCuaiu2pXctT1jCl14oE2/G
         hCkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678353340;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:in-reply-to:date:mime-version:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gRoyNf3kCSjJAS1UGGXCPrCbOy2Aux6+m1q9y1r3hDk=;
        b=6NWmNPmgg1TA4FeffxHFtnTgHXrOeVv4ObzWg940S0iszoU8JPclP4RCrjDQ6OBODM
         zmrUAzkx02x+axBTurrqkbly9cAqSdMbassChVDa/Z0ShgVPIXUIa2AkSg4isEzxsmUN
         QPVR/a2CfNblHG/7CkNWjWXTDik58Cd4kO3YGtHu4+vIHkEUwAbeYNEh1wB2dv7inN93
         mqqHtw+6ql2T/5aQVcoqYf7ryOoGInU8cGv2YyHhDMlOO8t8YRF6xjjAJiUlWCUNuk+J
         ocQOW09hOLmtBf3OAwpaef1DT5osr12aGsx3Z0QrjJQV7lCQPpoGOFaUSUhlV/b/OGM7
         kqag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVlrNbioeR9NIpb4G5QrkgDDgL38J2kZqQUA00HcWFUSn9QZytp
	kQDxFcRqixXg3dTCD0iiBoU=
X-Google-Smtp-Source: AK7set/KO4mjwNtYwUfz3pmBITVqbDUz5J501WiF9hZBt89NMJH5P7KmooZ67zUTrGUaJh6MqB8FWQ==
X-Received: by 2002:ac8:42c8:0:b0:3bd:1838:2596 with SMTP id g8-20020ac842c8000000b003bd18382596mr4201949qtm.8.1678353340492;
        Thu, 09 Mar 2023 01:15:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:10cc:b0:56e:9f70:6724 with SMTP id
 r12-20020a05621410cc00b0056e9f706724ls1054435qvs.8.-pod-prod-gmail; Thu, 09
 Mar 2023 01:15:39 -0800 (PST)
X-Received: by 2002:a05:6214:d66:b0:56e:a88f:70ef with SMTP id 6-20020a0562140d6600b0056ea88f70efmr40828025qvs.23.1678353339808;
        Thu, 09 Mar 2023 01:15:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678353339; cv=none;
        d=google.com; s=arc-20160816;
        b=K0nhRjDPGHpeY9UU8akzvKDJYBaWqLjYvHqvKlsL4h5ejZj4N+C+XO4ERefYlfZOEE
         A3uTayOt7S6BVzHaNpxU+iLp76+QeDJehBPi/DSAeBOg0eNvV3kpT5JAhuBR0mCt4I1Y
         pHG/zg4NhiZde3r4XNyL/v0VRdWS8IZrJQsCtupG26W71x5sL91lEFsM0nPal67LRuOS
         8nWcm8pJSIF2DkqN9jNepWMKkVn36OoIOioGr8s3GqBMmPKw4xMWegH8dLFAOIMIRLPj
         eyAnlEvyVRQgNPjuMsBuTnWb/gaBQfUibVe2y2DOTc1iJBlFOxAY8Mt41RUJlGuw7mTj
         zFiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=fHKEKHdPjoZhYVJRZoCAKKckDq3mCm+7VXF61UEPMbE=;
        b=bIth7o8lbhcQVw4rNNuPJMv24w5PGuLSEv7kOEOuNxC/8VCMcFFE0NQF5uI6J/4uc0
         JCNsCkZBOC7ZHGqwTzny3FdX3+kbsRknSvpUxMVsZT1qON/TxEsAKHAWM/Iv5PBmIzbK
         7X36asQWqF/HX764jUtcD9n0YP0Ir81jTswFa3NYL8mhxtJA/ZrvEHVRzU7KRaU3TjeB
         NFNyZ6Qwpt5+tAcSeo9u4SIr79xHUknug18v4fyxGz3H6eM1ypUnhwnZQlUfR8BkWhu2
         1Waj1IdSRvfYPABxbhPvD3NzCO0WW/AwsLoK+6LJUu478p+9ZBo0dOHlaSRfk2IPzKc2
         8tHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3u6mjzakbafaagh2s33w9s770v.y66y3wcaw9u65bw5b.u64@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) smtp.mailfrom=3u6MJZAkbAFAAGH2s33w9s770v.y66y3wCAw9u65Bw5B.u64@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f199.google.com (mail-il1-f199.google.com. [209.85.166.199])
        by gmr-mx.google.com with ESMTPS id dp12-20020a05620a2b4c00b007427cf877eesi760662qkb.2.2023.03.09.01.15.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Mar 2023 01:15:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 3u6mjzakbafaagh2s33w9s770v.y66y3wcaw9u65bw5b.u64@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) client-ip=209.85.166.199;
Received: by mail-il1-f199.google.com with SMTP id d6-20020a92d786000000b00316f1737173so634448iln.16
        for <kasan-dev@googlegroups.com>; Thu, 09 Mar 2023 01:15:39 -0800 (PST)
MIME-Version: 1.0
X-Received: by 2002:a02:942c:0:b0:3f6:e3c2:d4bd with SMTP id
 a41-20020a02942c000000b003f6e3c2d4bdmr5241040jai.0.1678353339389; Thu, 09 Mar
 2023 01:15:39 -0800 (PST)
Date: Thu, 09 Mar 2023 01:15:39 -0800
In-Reply-To: <000000000000fa5a2205b4c33093@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <0000000000009a1f7c05f6741666@google.com>
Subject: Re: KCSAN: data-race in tick_nohz_stop_tick / tick_nohz_stop_tick (2)
From: syzbot <syzbot+23a256029191772c2f02@syzkaller.appspotmail.com>
To: elver@google.com, frederic@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, mingo@kernel.org, naresh.kamboju@linaro.org, 
	paulmck@kernel.org, peterz@infradead.org, 
	syzkaller-upstream-moderation@googlegroups.com, tglx@linutronix.de, 
	will@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3u6mjzakbafaagh2s33w9s770v.y66y3wcaw9u65bw5b.u64@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.199 as permitted sender) smtp.mailfrom=3u6MJZAkbAFAAGH2s33w9s770v.y66y3wCAw9u65Bw5B.u64@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
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

Auto-closing this bug as obsolete.
Crashes did not happen for a while, no reproducer and no activity.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0000000000009a1f7c05f6741666%40google.com.
