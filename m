Return-Path: <kasan-dev+bncBCQPF57GUQHBBTUD2WYQMGQEMVKY6QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id E21F08BB467
	for <lists+kasan-dev@lfdr.de>; Fri,  3 May 2024 21:58:07 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-439846258c4sf153131cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 03 May 2024 12:58:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714766286; cv=pass;
        d=google.com; s=arc-20160816;
        b=EtzVMGcfFDIXozp2QR9pNMb7TWoX8TL+1KCTMNq9CnrZsFduZtkev+BI8521gokHcO
         SLICnbaLBoZlUbAO1azNeDNv/VL9EFZnhs4wX/8/dvuwGmp5sS6mQnK+fC/S+TP6Q0xJ
         Yb5sM+cS9BenNoHT1UiS70RQZqCMclZT9U41uGFST2N2TB7HQiMp06sv0GlqBFFBwEmG
         2Ms0CVxN9XqIK2zTZzaK/7iVmDi0lsW6TQ1GGUWBoH/WYRBI4GlgPGzzAO7jRfynYrhl
         5TKpz+oMdjxTSV3TtjCU4KjPldOStLfMoiKdRAwjPmANpzaCPddtS4P7aefbIGHnukJS
         SZrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=u6Mr9W91rJZd9pxaxfkRfLRdAhO5MtAoxxyJLCR8sBk=;
        fh=5zV0lSU4tibJZAjlAHC1YQDZhQvWoq/WO+e9wCkI+nI=;
        b=jiCCGVnba8qUXHvJ/yvZy6rQ0xTIdujCbhaPeChojYEAcwoGmhTp2NpyeFINGpVQ2x
         V7bP83ebKbpqnKNGU67EHgaJMM40Q/4kcDsH3vNzLlPGU9TfXPxua/tbssK8eZFxJdhP
         8kTvuYjog8k+MkzqDFDE0p+BFba/p7Kf3JH24h2pxuYqohppNkEpYt0vi2G0h73AID8E
         9UL/eqpx6ZlkW+n1vK/PG9oxrlJjWtajYjeIJQaZvjSyFPv/VMsWaqe98BD5E0aiDrLP
         hR9hcyWgr+gL89Szx9BsLmInTlEzhQ9lKLpEbnLlD11eyplEUL5xPCoBiODiBRHyJMcX
         femA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3y0e1zgkbafwmste4ff8l4jjc7.aiiaf8om8l6ihn8hn.6ig@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) smtp.mailfrom=3y0E1ZgkbAFwMSTE4FF8L4JJC7.AIIAF8OM8L6IHN8HN.6IG@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1714766286; x=1715371086; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=u6Mr9W91rJZd9pxaxfkRfLRdAhO5MtAoxxyJLCR8sBk=;
        b=OFYneFF6X3M2YiXpUQI4/BKtkPX2HE88xucqtzl5xV/zZW2Cse+O9DbSXGna54oPiv
         HnRclUPs/8KMppe87klwnWAyQRXh1KA8kTZbyIZxBibjWO7F8K8m7L2Ula95Gq7ceQVU
         p556Fie5XB+ZyorGQUguLSbk/hKJ+rA0qyU90dQkJR5TRSGeJEQBebYPv8wpOkJ9+Gw7
         G4eS3UDChJzKoueifGwDHa2TwsGeCKs3qVQESoDstR8pT4wgyR1T+X+hGW6NbPRnkE8d
         LZeeoFibs2zh4kDHfWUZynfJZXyNJBnbGhllTu+h/SB3zLyhNPetptJPDlkgl2GH4Yaw
         hVXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714766286; x=1715371086;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:in-reply-to:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=u6Mr9W91rJZd9pxaxfkRfLRdAhO5MtAoxxyJLCR8sBk=;
        b=aNs9NdEj1XXy1gQ9kWyuHDQNQww5vTnrT54VkewVv451pC5NcK5tQEiHtAHrrkLi5a
         RzEV/PL+Qi5QsWxkaDK2a9xZniWrURrItfOc0cCiJLVNMqdmob5J106MCH4FLDtjN0yr
         OgdSZncNZECHFA0YPEMrBrvd3pqU5I3ka/0NoUmgiE3ZwgBgMYtqzXzyVmkmP7dxHLSf
         aKwR0hSIi4CMdmcCHDKexkVj2d44wasZ72Tw4EnMFPWFIl+UNXmK8qDbMTtXz5z8/71j
         duP+H5uGKEBiATJ/ToEqV7W3jlasifHM/RkslpaKsJlc6Z5RDCvT85aTPQVDaAcc3U2R
         s6mg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXUH/WQiRVIkxNuGx7XuAJaYNN6jMLJbO3RjYI28H296/XRCG7Dq0VxoLY0YjdKEJtpAeqUdi9mVEIx34KzhRRRTpbca08fnA==
X-Gm-Message-State: AOJu0YzfvDbAfu/Bio3DIRQ7sgLQYVyGEQSLxMNMraOWMkKI7e5QmqpX
	3L9D5kFYoes3ImOzFsbaa0dwHsEo5Ds7YAZQz3k/+a3y6Wg8DtRe
X-Google-Smtp-Source: AGHT+IGnxteuRBm1po3ASHa/fJEiXL606z00ay9o/osUSiK0CwjgaMIWOLF61ngD/B03r2nwfiZ2eQ==
X-Received: by 2002:ac8:5a47:0:b0:43b:1472:167d with SMTP id o7-20020ac85a47000000b0043b1472167dmr3818543qta.51.1714766286605;
        Fri, 03 May 2024 12:58:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1922:b0:43a:c83c:f4cb with SMTP id
 d75a77b69052e-43ca8193d20ls23603791cf.1.-pod-prod-03-us; Fri, 03 May 2024
 12:58:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXzxtHTYdo55blApMTUmTSnR/9Ie4pVKAdft1lLBt3TY5g9/GprDHiQZoF/uHKyaWfN5FsVvW3wCFjIlICp6TI+4rJO/CtDOUHrLw==
X-Received: by 2002:a05:622a:301:b0:43a:b15d:bf69 with SMTP id q1-20020a05622a030100b0043ab15dbf69mr3728242qtw.46.1714766285743;
        Fri, 03 May 2024 12:58:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714766285; cv=none;
        d=google.com; s=arc-20160816;
        b=vBMJtooolvwSw+D50eZYWkTWVDO4X3UMDfUsWW9bKoOlyc1cX2FoCYo8dv3opMQFTa
         PNTb8pij9gJ8pEHrnnzQ7Kbbtn2jPRII9BgzP48F6U4ive7j11SFQxCD69+2NV1ChxY6
         oZ/CxYzwJytDzIOKryNF7EWA+qoT/EG9cbFQm4aDSyzP9lFJ0PN/lHUNpT4LeLI/J1tC
         d14mMZEOUv83M2UJZeU3WcVzvAKY4646SvrL8u0R5oVxIw6JOvyN7ep2Pz8+GTG02rTf
         Pf+F9hxAGfwVa/UnIjNds2qw9T8MSp8HujphIEdz3TH4l2m1ZeAtVQPUkrOt+TqMStC8
         pMrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=pwVY/fyH1gQuGakUUTvfCy/Q1T0f0xT1xNncswAUms0=;
        fh=JITXLQc8O9im/s2mQwKFuPcCJEMrg5+UJVvyyYf20Jo=;
        b=tOm8TsjVY01MPGEkeMmLLXvSLmmt8tM0gn8iu01Owgr14Y8TEK70uleI2BhRHUP+kp
         2ykkc3Mx0FzLqpnyhhjwCPQsLatkHKEh4n955YIS+EYoazzbDQkWWfzxvYBOcUv4XF1D
         hzRMB9CRvkNt2f9OAelj++zcP9UXLxU2+QptmfDLiVJfRBm17M0Ocw+R24sKVTstfEQh
         TIjoel2UTlt9001+XfPJmvll7+uaB79DdlaQaZMEByJ8JG8FervXSF5YymxOaMtmNW7J
         BzV7ugGHgPPNA7gnwdeGUaKdwtGPSdtlUN/DserZQGwycNjS6MTcO4T6F7A10ymz2tH8
         rzjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3y0e1zgkbafwmste4ff8l4jjc7.aiiaf8om8l6ihn8hn.6ig@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) smtp.mailfrom=3y0E1ZgkbAFwMSTE4FF8L4JJC7.AIIAF8OM8L6IHN8HN.6IG@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f199.google.com (mail-il1-f199.google.com. [209.85.166.199])
        by gmr-mx.google.com with ESMTPS id et26-20020a05622a4b1a00b00434ae42e17asi570636qtb.1.2024.05.03.12.58.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 May 2024 12:58:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3y0e1zgkbafwmste4ff8l4jjc7.aiiaf8om8l6ihn8hn.6ig@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) client-ip=209.85.166.199;
Received: by mail-il1-f199.google.com with SMTP id e9e14a558f8ab-36c7533ed44so704395ab.0
        for <kasan-dev@googlegroups.com>; Fri, 03 May 2024 12:58:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVeIBkH0IDI6myUayQU945qZ14xEf/CTM/tDwmL1ZxPS3RMidYwspuOqTBgn9rtgbwalx84R3DPprbAIvhEfSOmTOEVb8RLaMysbA==
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:218d:b0:36c:307b:7f08 with SMTP id
 j13-20020a056e02218d00b0036c307b7f08mr196694ila.0.1714766283713; Fri, 03 May
 2024 12:58:03 -0700 (PDT)
Date: Fri, 03 May 2024 12:58:03 -0700
In-Reply-To: <00000000000022a23c061604edb3@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <00000000000036c3d90617922353@google.com>
Subject: Re: [syzbot] [kasan?] [mm?] INFO: rcu detected stall in __run_timer_base
From: syzbot <syzbot+1acbadd9f48eeeacda29@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, brauner@kernel.org, davem@davemloft.net, 
	dvyukov@google.com, elver@google.com, glider@google.com, hdanton@sina.com, 
	jhs@mojatatu.com, kasan-dev@googlegroups.com, keescook@chromium.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, luyun@kylinos.cn, netdev@vger.kernel.org, 
	pctammela@mojatatu.com, syzkaller-bugs@googlegroups.com, victor@mojatatu.com, 
	viro@zeniv.linux.org.uk, vladimir.oltean@nxp.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3y0e1zgkbafwmste4ff8l4jjc7.aiiaf8om8l6ihn8hn.6ig@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.199 as permitted sender) smtp.mailfrom=3y0E1ZgkbAFwMSTE4FF8L4JJC7.AIIAF8OM8L6IHN8HN.6IG@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

syzbot has bisected this issue to:

commit da71714e359b64bd7aab3bd56ec53f307f058133
Author: Jamal Hadi Salim <jhs@mojatatu.com>
Date:   Tue Aug 22 10:12:31 2023 +0000

    net/sched: fix a qdisc modification with ambiguous command request

bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=13b9b317180000
start commit:   fe46a7dd189e Merge tag 'sound-6.9-rc1' of git://git.kernel..
git tree:       upstream
final oops:     https://syzkaller.appspot.com/x/report.txt?x=1079b317180000
console output: https://syzkaller.appspot.com/x/log.txt?x=17b9b317180000
kernel config:  https://syzkaller.appspot.com/x/.config?x=fe78468a74fdc3b7
dashboard link: https://syzkaller.appspot.com/bug?extid=1acbadd9f48eeeacda29
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=16435913180000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=111600cb180000

Reported-by: syzbot+1acbadd9f48eeeacda29@syzkaller.appspotmail.com
Fixes: da71714e359b ("net/sched: fix a qdisc modification with ambiguous command request")

For information about bisection process see: https://goo.gl/tpsmEJ#bisection

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/00000000000036c3d90617922353%40google.com.
