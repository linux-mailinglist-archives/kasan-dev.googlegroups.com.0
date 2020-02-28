Return-Path: <kasan-dev+bncBCQPF57GUQHBBBES4PZAKGQEQITO6UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id A49DD173262
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 09:02:13 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id r80sf279474vke.17
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 00:02:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582876932; cv=pass;
        d=google.com; s=arc-20160816;
        b=EB371YH6mBevjq8JyEM0PFBOb63mjO8MyJl8HXIVXKoR180c22ulfZv/4NHLSrMWOE
         R3iFRWvGi6rtcCR2OV7h3BklCxKD0nUWPwfzBGqhHcrQKGtIlAs6wpPZBN3H9rKFlPq1
         NhP4u0RfB1NMJWsx1AG6wMTMElpvw4u6CWTOaHsOE34e8TXA9+C1IXv/5sZsfpg3ZPxN
         z4LjvTPOB+m2R9JdYvf9MLNjNyC4035aTzsifFuCmmHc5+rbgiehvuAoHBuGrPvqKTyU
         G2EKkVVh5NONaUbwHeUyCYePSgk7SyWE9aQuB3zdWJk0gXB5xvHramP+Z0CEBS6ONcSU
         uTdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=monsOkgCOGyX7jV8A7GIO3yW8nAIic5sCUwAaZNOUOw=;
        b=HPzx9GIFZVhMeqdNc25T81sil5atJOEopHpU1+ktd/rHhV+FeDr2nZ3pHIa7flK4om
         PVrdIYBrO/m3tfAK9jUbiKxFQLGNxqXp0ywT0NA5NG0UGKvdOOscctP4hgpUh+q1t5V1
         tmG7aBnXvAklforLQO1qDgMI+xha5qO2eCOP01lISGICQdrvru032IlnO/eTKbqBEjBU
         YrMssMOxON3WHL3yAVcWk3CL26hLxGbPCMRsmbb8CJyWPUNYuVR5/LHMU2spObtUtwTF
         D6tttMSRcGCdFJc7pJCdHdu0Kc07F1aiL/GYy+LvYcYrBR6nggHdQbHrGWbljpiVVp+8
         dYsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3a8lyxgkbapakqrcsddwjshhav.yggydwmkwjugflwfl.uge@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) smtp.mailfrom=3A8lYXgkbAPAkqrcSddWjShhaV.YggYdWmkWjUgflWfl.Uge@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:date:in-reply-to:message-id:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=monsOkgCOGyX7jV8A7GIO3yW8nAIic5sCUwAaZNOUOw=;
        b=Tgvf/qJEZ8G9M/ZPPKsKhnAXgVx8G5/3O3ixglPULEWtYU4QrbC3+8/liQCLjZPvNP
         Z52euvX/LWwyaB+rzr/ijqKlgSmYwbYxwMkL1scPri7SNHdHoJwgz0GP5VqRqFYfE6x/
         7j5dpuGg0C3ffXe8ezLZuD46C1hrYruC3q87wXTXu8W5iDwxYlRth07i1uahGIDt7CTm
         kpRN8a6skbx9Hz+mroJI3rxT3T1bbKEhrnH/uhf/4lahdX0nhZAy89ivGB2wi/eMcaA9
         2QLpRPmOPUmK9nOP6y5CcTPDFcbNNUoYJzidNp3XLUiMGIrKRzCUphrhA1NlOxB1ViXL
         R5sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:date:in-reply-to:message-id
         :subject:from:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=monsOkgCOGyX7jV8A7GIO3yW8nAIic5sCUwAaZNOUOw=;
        b=nkRfSHTRSscQy2db4FLXiQx98X/rdtlJXOzpvIGTPDb05xKzMgEPMf3AahTFfYuPhB
         zM5MwFOEUCwGMi2bOCD7xkEZr2+Q2we0r0a1iz/8t206po7posrjgzkDw64yiMU9XaJ/
         hsUBYsTrHsl8gs2oGXtegdArEVgCMiasPg7czx0Dbdrhm2sB0GzH4jRjJw27Lu/pLfGv
         +932yobwR4fT8mzSJIxHh7dRAhsH6mBpD3QsilMU9Z1gIvXP1w6IZdGN3RgVlL7r8+6Y
         XTyDkRJS2V9FfBdtmasTPZvGkE6nbCSwvG/8hU5NynKuVYgpWit0Cx+hgMYG1zOYcHm/
         eGUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1l6aQq5qARr985uLhvUCMf79xq2nHsAR5uVXsIOOz6KuyOjWz9
	m8Zf8ohSXoQI7ui6TdEGGTA=
X-Google-Smtp-Source: ADFU+vunkiQZGfpLTrvxh/rNZ1G/zooZjEkiDvf0dKCHgtjIeNJ+goFPOJur6oJc1nGwiIZhNRmMBQ==
X-Received: by 2002:a1f:9e86:: with SMTP id h128mr1787355vke.44.1582876932686;
        Fri, 28 Feb 2020 00:02:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fdd1:: with SMTP id l17ls223031vsq.7.gmail; Fri, 28 Feb
 2020 00:02:12 -0800 (PST)
X-Received: by 2002:a67:ff14:: with SMTP id v20mr1898218vsp.114.1582876932320;
        Fri, 28 Feb 2020 00:02:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582876932; cv=none;
        d=google.com; s=arc-20160816;
        b=xmSnE2a8C/0SfdUvfklBPIz3bLX9gTsppx0ZLHe6HVqWAAs/QOPlTaRXy4vYSCSJKR
         Mj0frFMg80mP+xQD9QfKjZaUVNg0LNgid+l2EqFFP7w5UgJgFB7Gb5egJbfk3IhTvKlz
         vfhceM3rHw/udUkYl/4KNrqoERCggW1Wj3zSqr6a8WX3uGsRjnjwYldRe31iLPhdQ/w+
         E3F6PLV1u5RRyuNLYwdxtOBxMmsni7ZViwSc7mpS9r2oHwYEe6LVy0CGNzZavecVdR39
         pgmduEnKihLccuuIf1nkFVgJwMykkJPntf3FhiEkqp5RjWF+ZiHPScXNhflZSCV22Yxl
         tEMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=1F6QPB2AKxQKkbwngYuex+ythgWDXEu9f8wBzkprX/k=;
        b=k01u4174u+wLY+4ZcYLBK5B33tX2bAcHGjSo3/2+CM37B8su17uzLwUop13opGjc0i
         uQBv9vDe+fZCLEIb8uH68Y7HgdqZra/0f5U5nApw1UQ6PjdSNhy7OuQOnGJdjPQj7tKA
         1XPnl7BkIcoxW+PXKYqw+KZfTIs7qSPV/HHIxa0nQvJnuHMhrk3aPoe2xdmhx5e7jje0
         BCPP/uP42Dlp1ZAXV91+l45PiT3lCAtRPwoj/hzKkAm2GG78rIL4ivweHkUMBgc7Pl3y
         LK0pnppDUOGf9VjDk5ef2VmOUOwB/dgXTZs9x4DbQcYJrtoAB2ocmhK9NZrsHqr9eayr
         CPDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3a8lyxgkbapakqrcsddwjshhav.yggydwmkwjugflwfl.uge@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) smtp.mailfrom=3A8lYXgkbAPAkqrcSddWjShhaV.YggYdWmkWjUgflWfl.Uge@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f199.google.com (mail-il1-f199.google.com. [209.85.166.199])
        by gmr-mx.google.com with ESMTPS id 9si176309uau.0.2020.02.28.00.02.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Feb 2020 00:02:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 3a8lyxgkbapakqrcsddwjshhav.yggydwmkwjugflwfl.uge@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) client-ip=209.85.166.199;
Received: by mail-il1-f199.google.com with SMTP id a2so2539289ill.13
        for <kasan-dev@googlegroups.com>; Fri, 28 Feb 2020 00:02:12 -0800 (PST)
MIME-Version: 1.0
X-Received: by 2002:a02:9988:: with SMTP id a8mr2420608jal.33.1582876931843;
 Fri, 28 Feb 2020 00:02:11 -0800 (PST)
Date: Fri, 28 Feb 2020 00:02:11 -0800
In-Reply-To: <00000000000080f1d305988bb8ba@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <0000000000003eeb63059f9e41d2@google.com>
Subject: Re: BUG: unable to handle kernel paging request in ion_heap_clear_pages
From: syzbot <syzbot+be6ccf3081ce8afd1b56@syzkaller.appspotmail.com>
To: arve@android.com, christian@brauner.io, devel@driverdev.osuosl.org, 
	dja@axtens.net, dri-devel@lists.freedesktop.org, dvyukov@google.com, 
	gregkh@linuxfoundation.org, joel@joelfernandes.org, 
	kasan-dev@googlegroups.com, labbott@redhat.com, 
	linaro-mm-sig-owner@lists.linaro.org, linaro-mm-sig@lists.linaro.org, 
	linux-kernel@vger.kernel.org, maco@android.com, sumit.semwal@linaro.org, 
	syzkaller-bugs@googlegroups.com, tkjos@android.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3a8lyxgkbapakqrcsddwjshhav.yggydwmkwjugflwfl.uge@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.199 as permitted sender) smtp.mailfrom=3A8lYXgkbAPAkqrcSddWjShhaV.YggYdWmkWjUgflWfl.Uge@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

This bug is marked as fixed by commit:
kasan: support vmalloc backing of vm_map_ram()
But I can't find it in any tested tree for more than 90 days.
Is it a correct commit? Please update it by replying:
#syz fix: exact-commit-title
Until then the bug is still considered open and
new crashes with the same signature are ignored.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0000000000003eeb63059f9e41d2%40google.com.
