Return-Path: <kasan-dev+bncBCQPF57GUQHBBJMS4TCQMGQEI5XT75Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id EE2E2B4307F
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Sep 2025 05:36:06 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4b2f9e8dca6sf11370541cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Sep 2025 20:36:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756956965; cv=pass;
        d=google.com; s=arc-20240605;
        b=EcnSAK0VRh0L2/xOZgAhUcyYRKr/oZ2FTvA1AbP3+uEVk2Kj6f1gJ0J1WZaN/Gm6WK
         rTKrcV3GeI7i9tYGxAgkxp6oU0GemzX1HecrC0rUoKlnlvCH/ZlgSvLTuVcLg8fMxp8y
         Lxu4O9Ci3koX2p2bwxa+fW/aC/PD1rd7uZIwqndwXofbw0yiWed1YqkH9l/6WGkVNKjA
         6k47jYzwF5AaXivT5hCqOicHspbnNM0IaiYaqoXvADdxHuuZH9mYFzrWe+fk11njXXFp
         kdxF/N/W8OSAIuh2TfvYJJo7g638Nnol6VZq7DCTZeekYpkl5mRoq0F1wFp3idOFdCo1
         /XDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=d3xZoV3ZPwDqm0CEowX6dC32Kn3NthgZtxKiawnnM5Q=;
        fh=XgTH6MTSXIkoM/bbqmqWKRP++6NNSpAPwXopVUcMQik=;
        b=dtJh77Id8qbGj0TD6Ad+5xQuIvPZJIz1YviaN3rbxcKg/HwP6Oqro2zjV/1wrQe9CS
         weDMqXdhEgAYbh3HWwn/diy6AaakYGA4PT+V4Er5X7sTtB4V7HX4R2k7X5lcZSw++Nw6
         SLms39oSnyfaF88d1N2BxAZ6T4j5qTSm/SFBvqt0hJaAah6dphrGvzHYON24Jwwlz2Qp
         sHHzwu1PHZyPYEu7xqHhPTXlYpmzS0epPm4tTpgqerUI7B26OolcRfPflXemu86X0tXv
         VPAcS9Bs7e0JKI+wvLsYhEZUfWPQqPpedCpdMjhQ9umb8RPi4FL1De6x6jqgv9EY/aI1
         AXpQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3iwm5aakbagywcdoeppivettmh.ksskpiywivgsrxirx.gsq@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.70 as permitted sender) smtp.mailfrom=3Iwm5aAkbAGYWcdOEPPIVETTMH.KSSKPIYWIVGSRXIRX.GSQ@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756956965; x=1757561765; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=d3xZoV3ZPwDqm0CEowX6dC32Kn3NthgZtxKiawnnM5Q=;
        b=Arg5u+JuDY5l/Tp/6E1baUjwP6a6W7WchNtD8/vNN/esTPAZZjeVLKrtBgQDZ1pSIc
         EN45mE9312CpPVrSZZ2LhrUyvEQQSpU19SaFc6x9nnMb5M8HDiPdEohRe8Mipijz8vM6
         93wyHbFZvGdF79E9fjVDUdDv24rca5y4uKTfcyYy76LZefMJnScROPkdo3BfRlkvZ/4e
         WySjdC/XFzSSJkxBTzoBP8M4cUw5njBzU+gBjatR3JsDhROiF21PJ8ZvWpA5K0h5EIgK
         hYxxRImKCUqUWt2WVq3p2X1bZt681htTPeY26Nl87QwI0Pzonz9I7rf6hj9LU99ub0yJ
         ct2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756956965; x=1757561765;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:in-reply-to:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=d3xZoV3ZPwDqm0CEowX6dC32Kn3NthgZtxKiawnnM5Q=;
        b=A4tikkUTYZT8Au/Vi4j47U7vYa82bKuJJ6D/DZlOf5+1B77QEn7WC22nzenfLmlqs1
         /Jl1n5B1mdEYeXeBCI2TpeYSigqT77AAYzRG2JU7IReQqbREgUlHL/HBrFPk+GL64uSn
         2kO2HSTv121ImwczXj7hoMVq3Y2CZGkPb3RsfSwcMfkWU8aKfXQEiVHMSQRwXvDx1rk9
         FhKYZwN91hkW2z6Uc6a7jAuBm+URi66BWz2UXGaNevgY86K7EdS+SjP5FeiVgNQzM0EO
         zC0sUkA7qYcuki1brrzJmbGdcBoc5QMs7cHMOt8cKa17h+Ix1B4L8PtkXceGizI9j+R+
         8coA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWXc/H+5HzE2/prwXSFdUbeZGCi27QIrFmdTucSsOF570gZWCZAXyO1znXzbYrBEmgcWqyjxQ==@lfdr.de
X-Gm-Message-State: AOJu0YzoRV1RCybTVJ4KeVie2kEbZExsOZk/2YZSnHY5NKGaQ6DDDGfY
	vkYgyDxQDNzVxXos7U0qai5v/Ey582y245CB3VJFm4eE1WYTpKhOGorS
X-Google-Smtp-Source: AGHT+IHXPzyY3BwJ8LFbpnmznLgxQsoZIVxClFNZKKq1Wm0QPHHdwJZ3sfIzpzOIj1Jyydyo0xSZfA==
X-Received: by 2002:a05:622a:2c7:b0:4b3:dddf:7ea with SMTP id d75a77b69052e-4b3dddf0b2bmr88316491cf.27.1756956965457;
        Wed, 03 Sep 2025 20:36:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdq9PON+JZL09WwQdXlcB9krOIZpFni8qAkImlR0CWzUQ==
Received: by 2002:a05:622a:589:b0:4b0:7448:c7ee with SMTP id
 d75a77b69052e-4b2fe8ad7aels129394211cf.1.-pod-prod-03-us; Wed, 03 Sep 2025
 20:36:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV3WHHEF4Pfzksj9Uz8rKvAlJUbfNt7k/0t7wZh2BZR+MUEMo1BLe7z1UZivPjyT4ZyEFCpYLlQ6zs=@googlegroups.com
X-Received: by 2002:a05:620a:4103:b0:7fb:d114:94e8 with SMTP id af79cd13be357-7ff26eaac85mr1848377285a.2.1756956964528;
        Wed, 03 Sep 2025 20:36:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756956964; cv=none;
        d=google.com; s=arc-20240605;
        b=K5NJQanmnuUbCFk4AeeUkT8efMqmSMy36TzSxqSFH5VadyuxiWSiqREi80ERKlTQHr
         iOsLKnadMkIKW03T1BpFVPjmC5Gz664TdnyLjoQ48aZCD5R8SH2aTAdgSbJ6Z728xxdk
         1XB/Bht2EA8A77d1Qxh3otWbfQH3mAL/at4hBVRsbqBf0kYHlkvwdEVkgHJgqPlWDIRX
         CWvU6H9hcxNH7PXGeevF1VJosiO5fVZg5fd4NKTFkpvP6/vSOI2iKaJTJiFFOYd+mSnA
         mGg6q70IjnZGjXlgkZNzs38ui3+oX25prPNtbT1SA4JJsLY2bJmypRVl6cceKJwHKKHT
         AKwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=3kJIQbdDjMaKIwu8/RgGFYQ3IVbCoHpKFlYMG3WTfzE=;
        fh=zvDRHJ55BZiZoFypA+xUsG0d50okkq/gqHxVdzMQOWw=;
        b=C1ETAP5tuPzK54MeUMmCbxB+dNswndGpLLDekBe1zfNzF0eJ4FxXvDzOFSwgY/9j/x
         0X1xwGWPgkcqxA9ZNDGqK3avh62xzUOhTPzVqE3Pbtc/wHvXrNUXtS/jAqiXIjL5mJJS
         Oa2NgOECHwvTe/04vpxsco3ST2QH+FOnsNXN59Zk+W5htFKUC99m13zx7oYsyr/57J9Y
         u6wMj+XEu5yTHhgs/JDkHJso3dNG7h18blcmNXeK28vseGGtv0awufw9yuA0tnbDDomo
         /yycLgcW6J0sDW64Z0VohJ2eu98wmJnAWy4HniXWQwkbm1FL8j7WiUmR8G0tH8++czyl
         FOzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3iwm5aakbagywcdoeppivettmh.ksskpiywivgsrxirx.gsq@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.70 as permitted sender) smtp.mailfrom=3Iwm5aAkbAGYWcdOEPPIVETTMH.KSSKPIYWIVGSRXIRX.GSQ@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-io1-f70.google.com (mail-io1-f70.google.com. [209.85.166.70])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b48f657ae2si1867711cf.2.2025.09.03.20.36.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Sep 2025 20:36:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3iwm5aakbagywcdoeppivettmh.ksskpiywivgsrxirx.gsq@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.70 as permitted sender) client-ip=209.85.166.70;
Received: by mail-io1-f70.google.com with SMTP id ca18e2360f4ac-887280cfa52so62409739f.3
        for <kasan-dev@googlegroups.com>; Wed, 03 Sep 2025 20:36:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVUymKrP5LvD3JDl3O7wspMxpAMROgiS1xKgTbXwmPT4Uo7aH6ixM7gyi0UcrLeJlY7gfYgScljUXA=@googlegroups.com
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:4903:b0:3f6:5621:fbde with SMTP id
 e9e14a558f8ab-3f65621fe5fmr164563825ab.6.1756956963928; Wed, 03 Sep 2025
 20:36:03 -0700 (PDT)
Date: Wed, 03 Sep 2025 20:36:03 -0700
In-Reply-To: <000000000000939d0a0621818f1e@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <68b90923.050a0220.3db4df.020e.GAE@google.com>
Subject: Re: [syzbot] [mm?] INFO: task hung in hugetlb_fault
From: syzbot <syzbot+7bb5e48f6ead66c72906@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, david@redhat.com, dvyukov@google.com, 
	elver@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	keescook@chromium.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	mcgrof@kernel.org, mhiramat@kernel.org, mhocko@suse.com, 
	mike.kravetz@oracle.com, muchun.song@linux.dev, osalvador@suse.de, 
	syzkaller-bugs@googlegroups.com, torvalds@linux-foundation.org, 
	vbabka@suse.cz
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3iwm5aakbagywcdoeppivettmh.ksskpiywivgsrxirx.gsq@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.70 as permitted sender) smtp.mailfrom=3Iwm5aAkbAGYWcdOEPPIVETTMH.KSSKPIYWIVGSRXIRX.GSQ@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

syzbot suspects this issue was fixed by commit:

commit 2ae1ab9934c785b855583e3eabd208d6f3ac91e1
Author: Oscar Salvador <osalvador@suse.de>
Date:   Mon Jun 30 14:42:08 2025 +0000

    mm,hugetlb: change mechanism to detect a COW on private mapping

bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=1289ea42580000
start commit:   87d6aab2389e Merge tag 'for_linus' of git://git.kernel.org..
git tree:       upstream
kernel config:  https://syzkaller.appspot.com/x/.config?x=fb6ea01107fa96bd
dashboard link: https://syzkaller.appspot.com/bug?extid=7bb5e48f6ead66c72906
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=17dd6327980000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=16d24f9f980000

If the result looks correct, please mark the issue as fixed by replying with:

#syz fix: mm,hugetlb: change mechanism to detect a COW on private mapping

For information about bisection process see: https://goo.gl/tpsmEJ#bisection

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/68b90923.050a0220.3db4df.020e.GAE%40google.com.
