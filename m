Return-Path: <kasan-dev+bncBCQPF57GUQHBBJECXWXAMGQEHF4WBHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A109857ADF
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 12:04:06 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-21975b23f71sf2187332fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 03:04:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708081445; cv=pass;
        d=google.com; s=arc-20160816;
        b=FG9Lff86GUvMlJj0EQyoGPYm3wMpRF0EGTr7Vs7UBxn66dasWjxH79ouZkZQczgYHK
         dR/cGyBDva95nqCpqwlHC7cS2LG4Mk1pi3aI2aqqB0DuVFIyixnN7tXzRRGLWxNzF1/x
         kDYLl1BjTaclh9xov7E3B44kC10MJPftJxEO8TyzkIr2KESj0+8/LojSATbAe2/LrQiA
         ym8DMvcUANmmu+Rrg38UvcbeGxhY6x3X5OD3A+PqtOU1i/fgC6o7r1YK1Ij/rCIl14mD
         oXZuAT/Hcf+5AZPskzuaZnzqM+E8WItuMfInGRW6xvYdql7hTLQ1zAJ0ym4pf1wme9CE
         NjLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=iO5OuACXBe8UA8+U+K+R1UIZUYbwQ0P3kY/Bh7PWLs8=;
        fh=KzJzF+jsYXxWNRt2w9BO1XnNk06wiBLQ6muJoehTJ/A=;
        b=aReVCmz6vnRjwJg7zGjLpCxbChPae5pp3GqKp29DI7ekVP2Hye1t54DgieadWtF1UO
         aDdXvhneWe8tEGklDaehCqrDoGCOi/p1bXar2hXJTir1hFgjAcd+vCR/jml2Wx+P+lhT
         /H3J6/aou8G6/XZ9RAcyLf07tIQYYg3HdJ4fTLrzfEi+r0VVMhUb/5FJvLYVgfVFtRB1
         395ECIv8OWW/45syNrahq/nh10xZQcbOY16w67axeYsZFtibCyXg5FyCcGZBg2/ui9d8
         WloLAtBQXiM8Vz1QSfGldbXWUBvoAjHrTofRGK1kQudwMImYPj8JfKc75lkAWfiYSBeM
         zggA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3i0hpzqkbabggmn8y992fydd61.4cc492ig2f0cbh2bh.0ca@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.198 as permitted sender) smtp.mailfrom=3I0HPZQkbABgGMN8y992FyDD61.4CC492IG2F0CBH2BH.0CA@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708081445; x=1708686245; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iO5OuACXBe8UA8+U+K+R1UIZUYbwQ0P3kY/Bh7PWLs8=;
        b=e+Hmgk4xszOUZ55oW2bNvQvYfjURHR9usss8cw32BCslX17RAPno10M+l+HTm8U39I
         wtIWmT7+Ug74kHn1byqqk9m8UYhts6oDzBdx4AirREjJluEcsefgJlMzGa2VIjtRqSHN
         WZ1jy+Lnbx+5d4khiQQ7GSLbWLYGfoQQQ70XdrhKRpoN47xC0bMeaQNXlDoiP9QD/Idj
         FY1BbPWoTgMO0WV28Ktdhf/Kj/NXsNnf5KyvBn5fSMpRIVx9GTsF4WK9HGZMsumWdrEr
         buNXVZtIwOkdQ+ak/lk0X/ZSgprKbKkn3qlAdyx9/kM08zAKcRj+NPzNhT74JsPEo3QT
         45yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708081445; x=1708686245;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:in-reply-to:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iO5OuACXBe8UA8+U+K+R1UIZUYbwQ0P3kY/Bh7PWLs8=;
        b=WSFRR4hPxLk026RhO9vOmM2gAQ68crUTSacWKO8Njj4zi/UW9PIjB2jgFUpSKcQYfp
         Bay/tJvYfuixd7vM/WRhUeWI3DmKkySZsBrAuIoSHA8fE2A3kn9kSTvE5EJvf+4WIK2I
         S9i7oEdbXnEKo8XJ5ehlUej7EY2KXE6/PZmdPJ1zKOQgclChGG+5HqlTGY89ReYicc1p
         UWYyE95xx9BBAUrpHhe0sue26shj6Q3QeZZlhDT9f7QTQBcJ08UCKVYAtAIWUiBMVYzh
         w1nXcqAaU6BbV4D8dljfNqOKzI2izShFl3AlCU18xNKdwElNTmKDn4xZ3kdMfYupMQlV
         iFYw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUoEKPFHgQxyR+kh8SwG6MLj/Ucch6xUxv1Twz0mQEv812e5Z2cHKFnd9+T3lZyFaFSmOikOT6SfvnkGMKSLLY6cgYQJakyyA==
X-Gm-Message-State: AOJu0YzytxDbHPqwakdRfJECeTGGRyR/M3DmtntTCmqnRUrq/FKKcJSc
	Bi/0HbIaM1iC93a/qgLVY8Hc0kdboH9jseOEI0xNWF8bmNoci4xp
X-Google-Smtp-Source: AGHT+IFQUhM+LSUFyYjm4CTqjgjDGTEW5dihQM09W00WOZ6VYrF68iDBRD72FlSWuAP+pSUfK98UTg==
X-Received: by 2002:a05:6870:1d07:b0:21a:b45:7b5a with SMTP id pa7-20020a0568701d0700b0021a0b457b5amr4844937oab.30.1708081444939;
        Fri, 16 Feb 2024 03:04:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:3a2c:b0:21a:216d:4818 with SMTP id
 pu44-20020a0568713a2c00b0021a216d4818ls804876oac.2.-pod-prod-01-us; Fri, 16
 Feb 2024 03:04:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWGsOBEjeoRC/6+x1x0O8Nz8VrPMBnKJ/afbC21jCH7z/jZyhT954DkdD+wRAJ+Sqotxxm/um6d5ZURANsPtdoCmsCniK/i9lPIfQ==
X-Received: by 2002:a05:6870:7026:b0:218:55c9:bb20 with SMTP id u38-20020a056870702600b0021855c9bb20mr5149208oae.21.1708081443838;
        Fri, 16 Feb 2024 03:04:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708081443; cv=none;
        d=google.com; s=arc-20160816;
        b=pjwyhWa4uN0wJPwgIRLVtQnNwjWfhwNkGDWmu2rQ5yG3LQbJTrs7yIoMnWlb0JRoDZ
         FD3mO67q6GKbqftKzlWjsDJVk4f9BQ/D+BgKERzzZ3TsbD3ZyCLRuMS0hWFKoM8UybTE
         URioy0bfRkZPQbbV9H6YUssCW1llwKuQiHbKtaNQGCsCcZFNFNWvnm5+rArKiC6Ra8C8
         AqXHAWCBaUMvZhQc5WmM2rLkcXEKGLprR7HnKWZMDm9J//nLDJuFfm9CpeWVaMbHS/KE
         KYbjj+4kbL6XtbylauMWv3p52syDxSuJHLgru35ae0Mgw1XTZg3RuuzPfeey912Db/V7
         BXdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=ypVqCIOJZ52Xu4aOA0DIn5jJ2/opLAVYWZUXa94QqUA=;
        fh=qE4SHognP281Db8ujHHr3A5ip0e8KwYlob8V6VYsCNY=;
        b=Pa2/DKCjpVHev9iHnMDHUATbozsKTagEs2ro4YjfUKSPHp5dYtYZpa0aNs6bLmcibA
         c2hCD81CrUzjs0LE0sxG5QBUvnJKmaCsEOqjBxCZQkHi6Hujyy2pShbrU4n/4rfbc8My
         5Nxbt4h86V8Zr9q/pJwwZTId0AZT9zEk4oncNGg3Jp0OAj8rVViZy6NJLlQuwKJ3J4IZ
         4oVdhK/gEwvLYcbSpZ/EsTmT+yGWUO3ipRCqAS6uurTWv0rKSaM2GULRQiQD6o6FU7hD
         uqb8QEeaVd4A5pt0Dhg9Ex5Az+bKZycCUlOmOEYJdIK8qAEQRzEPoD5Qpuw0nq30mWqV
         MhEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3i0hpzqkbabggmn8y992fydd61.4cc492ig2f0cbh2bh.0ca@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.198 as permitted sender) smtp.mailfrom=3I0HPZQkbABgGMN8y992FyDD61.4CC492IG2F0CBH2BH.0CA@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f198.google.com (mail-il1-f198.google.com. [209.85.166.198])
        by gmr-mx.google.com with ESMTPS id i14-20020a056871028e00b0021a216d3a62si252622oae.5.2024.02.16.03.04.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Feb 2024 03:04:03 -0800 (PST)
Received-SPF: pass (google.com: domain of 3i0hpzqkbabggmn8y992fydd61.4cc492ig2f0cbh2bh.0ca@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.198 as permitted sender) client-ip=209.85.166.198;
Received: by mail-il1-f198.google.com with SMTP id e9e14a558f8ab-363d86bef43so10939925ab.0
        for <kasan-dev@googlegroups.com>; Fri, 16 Feb 2024 03:04:03 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXCWVudvK5cssCsSrU8nUbjtO3C9QhNLDohNcIiM5iDkHsaoZ283dXc9s9WwjmEhgt2bE82EwRnj8emlB49jjPymCP3HhXGIRQo7A==
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:1c89:b0:363:e795:df5 with SMTP id
 w9-20020a056e021c8900b00363e7950df5mr331278ill.0.1708081443528; Fri, 16 Feb
 2024 03:04:03 -0800 (PST)
Date: Fri, 16 Feb 2024 03:04:03 -0800
In-Reply-To: <0000000000001f905c0604837659@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <000000000000b06c9e06117db32b@google.com>
Subject: Re: [syzbot] [gfs2?] INFO: task hung in write_cache_pages (3)
From: syzbot <syzbot+4fcffdd85e518af6f129@syzkaller.appspotmail.com>
To: agruenba@redhat.com, akpm@linux-foundation.org, anprice@redhat.com, 
	axboe@kernel.dk, brauner@kernel.org, cluster-devel@redhat.com, 
	dvyukov@google.com, elver@google.com, gfs2@lists.linux.dev, glider@google.com, 
	jack@suse.cz, kasan-dev@googlegroups.com, linux-fsdevel@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3i0hpzqkbabggmn8y992fydd61.4cc492ig2f0cbh2bh.0ca@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.198 as permitted sender) smtp.mailfrom=3I0HPZQkbABgGMN8y992FyDD61.4CC492IG2F0CBH2BH.0CA@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

commit 6f861765464f43a71462d52026fbddfc858239a5
Author: Jan Kara <jack@suse.cz>
Date:   Wed Nov 1 17:43:10 2023 +0000

    fs: Block writes to mounted block devices

bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=151b2b78180000
start commit:   92901222f83d Merge tag 'f2fs-for-6-6-rc1' of git://git.ker..
git tree:       upstream
kernel config:  https://syzkaller.appspot.com/x/.config?x=3d78b3780d210e21
dashboard link: https://syzkaller.appspot.com/bug?extid=4fcffdd85e518af6f129
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=17933a00680000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=12ef7104680000

If the result looks correct, please mark the issue as fixed by replying with:

#syz fix: fs: Block writes to mounted block devices

For information about bisection process see: https://goo.gl/tpsmEJ#bisection

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/000000000000b06c9e06117db32b%40google.com.
