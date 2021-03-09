Return-Path: <kasan-dev+bncBCMMJFFL5UDBBYF3T6BAMGQEADQOVHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id C4CC0333024
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 21:43:12 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id v5sf1636023wml.9
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 12:43:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615322592; cv=pass;
        d=google.com; s=arc-20160816;
        b=TvgWmZxWOb9iOlPUEo4j4aZX1J0JtfhpetOdwMk5JsvuV7zWsSMQ/DD4XaIybVJbJt
         3mfm1ZgaqZHkFaY7gzVqijpkerUaSEMmuSbW/4aTTDiitAQyCGn/7K9x/VEvOlBaGzmt
         Lk6ZefoVKkVMPBeqzEFsT7RZpp0Ubj1WITG+8/QihbgKGWtF0LIPcELVUMuJ8kd3KD5n
         GPu5eN2HoiCllZJVFNEvKaK+F9/cTni3BOYV1BrDLDthd+mk1LHdN9iwZWnmZHGFqX5m
         ctiqRHgvdFAURW1hL/HLLj4tnw6HKPcncyhNlJyvCfkuioZGPPOUfnXRj9F2zmraDrL3
         7a0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:mime-version:dkim-signature;
        bh=eXgSq4MGa2p7GF8R4r8Qw6zMlxOu5/b28Kj9OeYSu8Y=;
        b=B9aE0EqdcV4ffso0nv25M0K/adO2NZKR+4G6LXPavbi335Hc17LL3k2qCSzV65GbKC
         uyi6RxkMqI2vQ8FL3UXSU3EwCGMVa+zwDF2nKNl1pp6kiH9yNhYIqfIQqRcOUHaA84vA
         9R4GxcoOUGsdRiAiZUAyI3NBAKY3pCoPBcVjPPCsOs49oTAfaW6JaoShJVfWPGkVZ+q3
         5W8k/6sWCzQnF8dgzo8XnDvRtGrJY8KXcpIoM7JzVO+AqC6dezOIYI8pM/YgFQyFiOZK
         8wu6JjVzI6kGqmTpgAvR0SuEeFlz9w5BVc9LCnQJhOMn/L+C2CqqyI0eQlNR3sugPMpm
         0Ssw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lsdMpuNc;
       spf=pass (google.com: domain of jhumphri@google.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=jhumphri@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=eXgSq4MGa2p7GF8R4r8Qw6zMlxOu5/b28Kj9OeYSu8Y=;
        b=lIds4GGvq1CzOaH5FGYLhaFe4lIH09bSsjypFkGWK0+Ct5ifCV0d2thZMqnbUfWLmU
         YYGZFlb14wofRFlMSKolrFs8VBhmO3ve7Kbg1FKy0jz7GOvS/nLPcXhk0cpoN/rMvuTc
         2VxNyre31n5F6dnZcnILI+pqsp/MrZpjpED8xUaj8aK4C8piniZ/1rZYYwNXP4xcMQie
         hXqlbRMwSAxYda2fVguY5PTGLJE4jRUPvLrmnkr73Ki4go5ELRKfVXgF6BWDuitRxmdn
         hIgIjvu+tmy7QPLANd7xHR4uWJw9RC+2ez5BHMuh4sZ7RbduxVLHWaN5LFpbQoAVFvTW
         xm5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eXgSq4MGa2p7GF8R4r8Qw6zMlxOu5/b28Kj9OeYSu8Y=;
        b=m2u+pW783NO/os3eSEo7MLOGiMOFuaP0Q4fNQUBYqsHrSZLCMkZtVD6wmRutJD2073
         3cK6n8xkPgnRluNgq9ahvPhi9s7MPl8tFH1Af7HbAa5pshXlUG91oIfDb9yJKu3mRxTV
         OWQ2PAuGkpu1u+nI7QT61oHPQHyMqq1XHMR33bNewzPY2X1DPBkhgcnkZqarplnPRNdJ
         xmRKfuc5nA05So5KoCtBmZgnvucAMXrSh8vtEWF4uN5AMqOp8Iv1bduEemVxIEWa8DvT
         76SQGZgRFx15zRE19+aP7kHBGoTOr7Qqzt4vbXszSV6QJ+WYFY4aRvxI/+TYbH4EiDrQ
         +gEw==
X-Gm-Message-State: AOAM530mgFpwZx89Efv1Mn2VqnhUGTVkZJxavI3/lulKvRczppddKwn0
	cm0uoh4geL7IoeOZ1bNIF9U=
X-Google-Smtp-Source: ABdhPJwiPyWnhmp+kBpS4tX9BhKqs2GcFN7yADG9vAaKMOiG/eGCR3puD0Y4yisnVGkLvtrjQ02oZA==
X-Received: by 2002:adf:d205:: with SMTP id j5mr20614454wrh.211.1615322592510;
        Tue, 09 Mar 2021 12:43:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:60c2:: with SMTP id u185ls2133764wmb.2.gmail; Tue, 09
 Mar 2021 12:43:11 -0800 (PST)
X-Received: by 2002:a1c:7e45:: with SMTP id z66mr5971201wmc.126.1615322591661;
        Tue, 09 Mar 2021 12:43:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615322591; cv=none;
        d=google.com; s=arc-20160816;
        b=gtrG7vb27ViAagnYjsHAIMdGKZP4FRS4jFTGAUbfRlD/i4H9G/8GZKhKbuvQyQRuhP
         ItFWNMd3BW+JI7xIZJrIHxHmt9jXVihrnKl6wAIsPq8ubTJ4YK4VHB+ek8m4PBG3ZVaI
         qW8Q4rIvI6bG9knmO49I3sXsNt9NlDZBPL4nfY0wAN75OtkZQvaG6AEO9Ml1b25oVPEs
         +2DYYVtYpgP+jH8BcQIlSu5JylQL9/LqA6HcTwjPgQatchy/TcCLJtViRzLL1RbL7POj
         wgtrEJGQ7eq9/jH5qwTa0tbnZjbO2ptDc5AGQ5hQcY12r3t0q35CcXNBRnjIeOUDpMpf
         TGrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=8r0ViUjJmdnMr2I/n8DQniB5gALNh8NdQ56Ox2g0ag8=;
        b=h4jrgeB0zGNjijZ67/hYYQCI4bNUrkwAktui2+KuzpULOVhT6c2tY8N9uH2z1F2n6Z
         hSG3vx6Uen0wNvRnpjwjs8qPwMpwaUDyq5TMUT1sqrioOz3m0VqxWT0+Z5kxmV12Rs/r
         NxJP67T8BVydxJaU8WbGT0qxCRkdtE8XaEwOd8LP8uFOb4nEPpCxCRkEmiy61DoKLhMm
         Ptbcc11sch99/o9095oyEDxaUw/wBivlJCVs+wKB/hHRFqnOsqHJdSMO7qi3Nu24HIIN
         gHuTobHX39GEx3W7k/pxP3BzR9EYukexh2yz88lZYdcUHh/jY1tv48VieitOGIDMrH9w
         V+OQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lsdMpuNc;
       spf=pass (google.com: domain of jhumphri@google.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=jhumphri@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x531.google.com (mail-ed1-x531.google.com. [2a00:1450:4864:20::531])
        by gmr-mx.google.com with ESMTPS id p189si137115wmp.1.2021.03.09.12.43.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Mar 2021 12:43:11 -0800 (PST)
Received-SPF: pass (google.com: domain of jhumphri@google.com designates 2a00:1450:4864:20::531 as permitted sender) client-ip=2a00:1450:4864:20::531;
Received: by mail-ed1-x531.google.com with SMTP id h10so23091744edl.6
        for <kasan-dev@googlegroups.com>; Tue, 09 Mar 2021 12:43:11 -0800 (PST)
X-Received: by 2002:aa7:d642:: with SMTP id v2mr6359329edr.257.1615322591107;
 Tue, 09 Mar 2021 12:43:11 -0800 (PST)
MIME-Version: 1.0
From: "'Jack Humphries' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Mar 2021 12:43:00 -0800
Message-ID: <CAAjQ+WqFdpaWOjjDxVTU7bFL=-w8zYvp1OM2EXCNY0WeGszppQ@mail.gmail.com>
Subject: Open Source
To: kasan-dev@googlegroups.com
Cc: Paul Turner <pjt@google.com>
Content-Type: multipart/alternative; boundary="0000000000003df84a05bd20996c"
X-Original-Sender: jhumphri@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lsdMpuNc;       spf=pass
 (google.com: domain of jhumphri@google.com designates 2a00:1450:4864:20::531
 as permitted sender) smtp.mailfrom=jhumphri@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jack Humphries <jhumphri@google.com>
Reply-To: Jack Humphries <jhumphri@google.com>
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

--0000000000003df84a05bd20996c
Content-Type: text/plain; charset="UTF-8"

Hi KASAN team,

I am on the ghOSt team at Google. I have received approval to open-source
our project. Our project contains both kernel code (in prodkernel) and
userspace code (in google3).

I have questions about open-sourcing kernel code in particular (licensing
headers, copybara, etc.). I know KASAN has open-sourced kernel code before.
Is there someone I can connect with on your team to discuss?

Thanks,
Jack

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAjQ%2BWqFdpaWOjjDxVTU7bFL%3D-w8zYvp1OM2EXCNY0WeGszppQ%40mail.gmail.com.

--0000000000003df84a05bd20996c
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hi KASAN team,<div><br></div><div>I am on the ghOSt team a=
t Google. I have received approval to open-source our project. Our project =
contains both kernel code (in prodkernel) and userspace code (in google3).<=
/div><div><br></div><div>I have questions about open-sourcing kernel code i=
n particular (licensing headers, copybara, etc.). I know KASAN has open-sou=
rced kernel code before. Is there someone I can connect=C2=A0with on your t=
eam to discuss?</div><div><br></div><div>Thanks,</div><div>Jack</div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAAjQ%2BWqFdpaWOjjDxVTU7bFL%3D-w8zYvp1OM2EXCNY0WeGszpp=
Q%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAAjQ%2BWqFdpaWOjjDxVTU7bFL%3D-w8zYvp1OM2EXCNY0=
WeGszppQ%40mail.gmail.com</a>.<br />

--0000000000003df84a05bd20996c--
