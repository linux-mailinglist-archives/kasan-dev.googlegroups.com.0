Return-Path: <kasan-dev+bncBCQPF57GUQHBBPMOXD6AKGQE4ZUYOVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id B663C2930A4
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 23:38:06 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id k18sf457805ots.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 14:38:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603143485; cv=pass;
        d=google.com; s=arc-20160816;
        b=ob0hRVsinjN5JPXGlL6BT7mshRZgqfzZEHnTvrcXIPLitrqD15AeQiLkKnTBsFTAoZ
         nGvJH5RSV6HQD6pToNWdB5lo5aMA/DWuPzy1WMa2Kr02rccQm+U6PaSmcFbDOflV9vLL
         k53Tlr86KSc1NuaWC4MkObJhrx5Eat+9o+rlzSP3NGjj1Kws6/08qTvVK+1rmqkv0JBA
         XX+P2J3Q/ewixD5j19lijxtE6ToM42zU1g3R1pUozn4pHd/VUjLz/Tig0NgIrdS1AxO8
         UdWJotcgLFCroWuJXvQdnZI0oaPQzEF+ZN8eiEnjyXf0OpcA9IqSrqi2ic+uiTLrv5q4
         F+ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=wrbcm9QBgHO5/fQD+xS0eQnkr7VyOxUEU+mN8ad+Sog=;
        b=eLjr8enj0XvMp4BzIA5QIXXuo58AekhinyVvu2VvrQ2vtm33JHsrBegpgSxHm/NHg2
         oBF8xk78O0wauOkCvJ7uhGUvE0RV9N1RLmNZ/9X2E8ox5fo2G4jpHY57181JBF8aUy6f
         +hgm+vK4/aJyZpJW+0bnd92xxBTSQ8WlWmHBSjVyKhUfpuPEmrJ35jCyxYcgheTTk90i
         X3U/zuCOEag5xAjLcDMyQC1xT9+l/DsKFSFXCQMmZrv3FJXqKnz686vHu7BIniCpUTwx
         aoxV+x0czDq4Mir+Io0RgJkIR8Xk51vQP1qdj0RrMqrudgpXfgJ6NgbiXdTYNEw5NOSk
         DwCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3paeoxwkbaiu178tjuun0jyyrm.pxxpun31n0lxw2nw2.lxv@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.71 as permitted sender) smtp.mailfrom=3PAeOXwkbAIU178tjuun0jyyrm.pxxpun31n0lxw2nw2.lxv@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:date:in-reply-to:message-id:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wrbcm9QBgHO5/fQD+xS0eQnkr7VyOxUEU+mN8ad+Sog=;
        b=CcpOK2H/g9KCG0D6X9wn5/Uib0jsiOjPNV3vOwJY9XNjyaG692VMmlES7z8ST//60T
         h0ldQR5yy7WGa+69fSX+ZYW0KEMXGrKPEmCZLy7QYoefy0Ua9esVoGQZal5/5fl6cemr
         AvTG8IOB73qX51aQnBZQQnhe1wEoKQWh24A+VHu7XN2+ZliBJChsDzuCf2ncHGAGCm74
         pGNm4E0M3rHQCfDGwBjakIglnF3R5BMXFfN+ucd4o5tfxw5L/f2AER5XeUwN23bLBwxT
         //jla3zr1WRTSa+LJdOnBFLLjxSSmJlPlGYX3Yc/Shoe/knnRPJWeqM8neKKCE8dscWO
         KJ6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:date:in-reply-to:message-id
         :subject:from:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wrbcm9QBgHO5/fQD+xS0eQnkr7VyOxUEU+mN8ad+Sog=;
        b=nWBRKQTFpS9Im1PoN7PoI7XnkWzKF1TGrE14MO7sBgYkjQvx5TD3wHXddIamK5r6wN
         mUIcvPHsUW+IG+zZ00OK+HEWwkZB2oJX0zhsj4xNrfxvH2Z5ZXxId7MHpamlP8a3GaoT
         lcHloa5/QTzn8ZXI89xXcFGbfWMfJeMytNo7Y7M7Z3D6v7DOhdFniOEGUeR8BvHHNYFL
         ycnAR9wqWVV9YWUCB7EX7I5vfasBiY43zs6G5pejx2huUMAvnKdfp4hpl0ta9n88+2py
         psM15SpKaXJ3PbEH1XV4yro3dpzsWuI0vH/LO9vIKXTLDDBOC+IGs6pibpALvY8keefi
         a1Gg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530mEewTcMNVK4ahp0jGu6d299Vp7zxga9G15N5k8sBPO9OGmmw0
	eQlZXCIFPbhr1B1JzP2TVM0=
X-Google-Smtp-Source: ABdhPJxPMLo+kI2GqNRU2CvrXdhhOHTpsFHWjLUC16SXOtsyrDmb8IShbFG+kQmJv7XxWp/mgp4OdA==
X-Received: by 2002:a4a:ce90:: with SMTP id f16mr1402773oos.55.1603143485617;
        Mon, 19 Oct 2020 14:38:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:20cb:: with SMTP id z11ls217639otq.9.gmail; Mon, 19
 Oct 2020 14:38:05 -0700 (PDT)
X-Received: by 2002:a9d:7c87:: with SMTP id q7mr1412047otn.140.1603143485180;
        Mon, 19 Oct 2020 14:38:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603143485; cv=none;
        d=google.com; s=arc-20160816;
        b=ZJKRG8OYw4OcilMKsJ+jhqXISE4SA4UzWpAOcXKqi7kYA2DCTDG3Ia30xZayjX6U43
         et7CW49p1W40ob78lyEpclr/uAWCJ8pSctfwy9DvIMnAx8ziMs5V7W4gabdLrzX0fR61
         z166CYW1SGe9Jq7O6MBRGGFYunuPNlrSWHraTYpI737Rgz1TuY/vDgul9C3Dvb4P1fYw
         ZbYUYklDIsqH+Z1LwIoSGsmdwiIKpQM6illNIO5kfWshNj5l14A1LjzTdDlK5rYDIOsg
         hqxhjOEkXFfun6tuR+QAwlCHNgbYb15pwgOY98X/YCgPKCAuaS68w7wjHLT5NNULSRGu
         Tzjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=3+pOrgaRKys1ukxYUhRD8eMBk03/5Wr4iYqe05uE/Xs=;
        b=Qjl+3kPJivkQYk18dunw9wbfcKSQstT5fCQfY9vf/U0Kk++NGRm1LBV+FMLASsMChb
         LqzhG1aIqeryfDa/KXEYzat059qNl/zVEpstW8enuCMTdmzcIG6/viwA3jrZkk0q1hgs
         w91bnmQtioCOfl75cAWEyJdVSXbd5ICK+giGb0OuVe6mTZZ1alQw1NwmuGau78zcE3Kf
         3VoBYv4solhgpOooxrfXe2JlbNxsHS449bFaRdQswI1MqOpMaOG1u7noM2JlwGRypj/V
         kSsDHWsBs6a024kf+VTCvNLd39yXQ59HnwaNU2iMWW9V645ng+asSOEFfUnZHMCermIu
         dfbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3paeoxwkbaiu178tjuun0jyyrm.pxxpun31n0lxw2nw2.lxv@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.71 as permitted sender) smtp.mailfrom=3PAeOXwkbAIU178tjuun0jyyrm.pxxpun31n0lxw2nw2.lxv@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-io1-f71.google.com (mail-io1-f71.google.com. [209.85.166.71])
        by gmr-mx.google.com with ESMTPS id j78si123732oib.5.2020.10.19.14.38.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Oct 2020 14:38:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3paeoxwkbaiu178tjuun0jyyrm.pxxpun31n0lxw2nw2.lxv@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.71 as permitted sender) client-ip=209.85.166.71;
Received: by mail-io1-f71.google.com with SMTP id k14so1188487ioj.9
        for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 14:38:05 -0700 (PDT)
MIME-Version: 1.0
X-Received: by 2002:a92:1801:: with SMTP id 1mr1325764ily.219.1603143484870;
 Mon, 19 Oct 2020 14:38:04 -0700 (PDT)
Date: Mon, 19 Oct 2020 14:38:04 -0700
In-Reply-To: <00000000000005f0b605af42ab4e@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <000000000000f098f005b20ced50@google.com>
Subject: Re: KASAN: unknown-crash Read in do_exit
From: syzbot <syzbot+d9ae84069cff753e94bf@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, aryabinin@virtuozzo.com, 
	b.zolnierkie@samsung.com, christian@brauner.io, dan.carpenter@oracle.com, 
	dvyukov@google.com, ebiederm@xmission.com, george.kennedy@oracle.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	mingo@kernel.org, peterz@infradead.org, sandeen@sandeen.net, 
	syzkaller-bugs@googlegroups.com, tglx@linutronix.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3paeoxwkbaiu178tjuun0jyyrm.pxxpun31n0lxw2nw2.lxv@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.71 as permitted sender) smtp.mailfrom=3PAeOXwkbAIU178tjuun0jyyrm.pxxpun31n0lxw2nw2.lxv@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

commit a49145acfb975d921464b84fe00279f99827d816
Author: George Kennedy <george.kennedy@oracle.com>
Date:   Tue Jul 7 19:26:03 2020 +0000

    fbmem: add margin check to fb_check_caps()

bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=17ce19c8500000
start commit:   729e3d09 Merge tag 'ceph-for-5.9-rc5' of git://github.com/..
git tree:       upstream
kernel config:  https://syzkaller.appspot.com/x/.config?x=c61610091f4ca8c4
dashboard link: https://syzkaller.appspot.com/bug?extid=d9ae84069cff753e94bf
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=10642545900000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=141f2bed900000

If the result looks correct, please mark the issue as fixed by replying with:

#syz fix: fbmem: add margin check to fb_check_caps()

For information about bisection process see: https://goo.gl/tpsmEJ#bisection

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/000000000000f098f005b20ced50%40google.com.
